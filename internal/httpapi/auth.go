package httpapi

import (
	"net"
	"net/http"

	"postlite/internal/auth"
)

type loginBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var b loginBody
	if !decodeBody(w, r, &b) {
		return
	}
	ip := clientIP(r)
	if s.Limiter != nil && s.Limiter.IsLocked(ip) {
		fail(w, http.StatusTooManyRequests, "rate_limited", "too many failed attempts, locked for 15 minutes")
		return
	}

	u, err := s.Store.Users.GetByUsername(b.Username)
	if err != nil || !u.Enabled {
		if s.Limiter != nil {
			s.Limiter.NoteFail(ip)
		}
		fail(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}
	if !auth.VerifyPassword(b.Password, u.PasswordHash, u.Salt) {
		if s.Limiter != nil {
			s.Limiter.NoteFail(ip)
		}
		fail(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		return
	}
	if s.Limiter != nil {
		s.Limiter.Reset(ip)
	}

	token, stored, err := auth.NewToken()
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if err := s.Store.Sessions.Create(stored, u.ID, auth.SessionTTL); err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	_ = s.Store.Sessions.PurgeExpired()

	cookie := &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.CFG.SecureCookie,
		MaxAge:   int(auth.SessionTTL.Seconds()),
	}
	http.SetCookie(w, cookie)
	ok(w, map[string]any{"user": u})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("session"); err == nil && c.Value != "" {
		_ = s.Store.Sessions.Delete(auth.TokenHash(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", MaxAge: -1, Path: "/"})
	ok(w, map[string]any{"logged_out": true})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	u, isAuthed := s.requireUser(w, r)
	if !isAuthed {
		return
	}
	ok(w, map[string]any{"user": u})
}

// clientIP prefers the direct peer address (trusted intranet deployment).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
