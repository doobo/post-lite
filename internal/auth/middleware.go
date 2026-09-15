package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"postlite/internal/models"
	"postlite/internal/repository"
)

type ctxKey int

const userKey ctxKey = 1

type SessionDeps struct {
	Sessions *repository.Sessions
	Users    *repository.Users
}

// Middleware resolves the session cookie into a user context.
// Requests without a valid session simply pass through; handlers opt in
// via User()/RequireRole.
func Middleware(d SessionDeps) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if c, err := r.Cookie("session"); err == nil && c.Value != "" {
				hash := TokenHash(c.Value)
				if sess, err := d.Sessions.Get(hash); err == nil {
					if time.Now().Before(sess.ExpiresAt) {
						if u, err := d.Users.GetByID(sess.UserID); err == nil && u.Enabled {
							r = r.WithContext(context.WithValue(r.Context(), userKey, u))
						}
					} else {
						_ = d.Sessions.Delete(hash)
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// User extracts the authenticated user from the request context.
func User(r *http.Request) (models.User, bool) {
	u, ok := r.Context().Value(userKey).(*models.User)
	if !ok {
		return models.User{}, false
	}
	return *u, true
}

// JSONError writes a unified error response.
func JSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":    false,
		"error": map[string]string{"code": code, "message": message},
	})
}

// RequireRole guards a handler, returning (user, ok) so handlers can use
// it in one line.
func RequireRole(next http.HandlerFunc, role string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := User(r)
		if !ok {
			JSONError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
		if role == "admin" && u.Role != "admin" {
			JSONError(w, http.StatusForbidden, "forbidden", "admin role required")
			return
		}
		next(w, r)
	}
}
