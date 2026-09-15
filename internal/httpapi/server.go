package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"postlite/internal/auth"
	"postlite/internal/config"
	"postlite/internal/crypto"
	"postlite/internal/executor"
	"postlite/internal/models"
	"postlite/internal/repository"
)

// Server wires repositories, the vault, and the executor together and exposes
// the REST API. All handlers use a unified {"ok":..} envelope.
type Server struct {
	Store   *repository.Store
	Vault   *crypto.Vault
	Exec    *executor.Executor
	CFG     config.Config
	Limiter *auth.RateLimiter
	Log     *slog.Logger

	// auditf, if set, records admin operations (stdout + settings table).
	auditf func(actor, action, detail string)
}

func New(store *repository.Store, v *crypto.Vault, exec *executor.Executor, cfg config.Config, limiter *auth.RateLimiter) *Server {
	return &Server{
		Store:   store,
		Vault:   v,
		Exec:    exec,
		CFG:     cfg,
		Limiter: limiter,
	}
}

// SetLog installs the structured logger.
func (s *Server) SetLog(l *slog.Logger) { s.Log = l }

// SetAuditFunc installs the audit sink (stdout + settings table).
func (s *Server) SetAuditFunc(f func(actor, action, detail string)) { s.auditf = f }

// audit records an admin operation.
func (s *Server) audit(actor, action, detail string) {
	if s.auditf != nil {
		s.auditf(actor, action, detail)
	}
}

// ok writes {"ok":true,"data":...}.
func ok(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": data})
}

// okStatus writes a success envelope with a specific status code.
func okStatus(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": data})
}

// fail writes {"ok":false,"error":{code,message}} with the given status.
func fail(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":    false,
		"error": map[string]string{"code": code, "message": message},
	})
}

// requireUser authenticates; returns the user and whether the request passed.
func (s *Server) requireUser(w http.ResponseWriter, r *http.Request) (models.User, bool) {
	u, isAuthed := auth.User(r)
	if !isAuthed {
		fail(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return u, false
	}
	return u, true
}

// requireAdmin authorizes an admin-only handler.
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) (models.User, bool) {
	u, isAuthed := s.requireUser(w, r)
	if !isAuthed {
		return u, false
	}
	if u.Role != "admin" {
		fail(w, http.StatusForbidden, "forbidden", "admin role required")
		return u, false
	}
	return u, true
}

// decodeBody parses a JSON body (4MB cap).
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20))
	if err := dec.Decode(v); err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "invalid JSON: "+err.Error())
		return false
	}
	return true
}

// idParam extracts the numeric id from the {id} mux path parameter.
func idParam(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	n, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "invalid id")
		return 0, false
	}
	return n, true
}

// itoa renders an int64 for audit detail strings.
func itoa(n int64) string { return strconv.FormatInt(n, 10) }
