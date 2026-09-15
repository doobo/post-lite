package httpapi

import (
	"net"
	"net/http"

	"postlite/internal/auth"
)

// loginBody carries the username plus the encrypted password envelope. There is
// deliberately no plain-text field: the server refuses to accept one even if a
// client offers it.
type loginBody struct {
	Username string `json:"username"`
	Enc      string `json:"enc"`
}

// loginKey (public) hands out the ephemeral public key and a single-use
// challenge. The browser encrypts {"c":challenge,"p":password} with it and
// posts the result as "enc" to /api/auth/login.
//
// "key" is the SPKI DER blob WebCrypto's importKey("spki") wants; "n" and "e"
// repeat the same key as bare numbers for the pure-JS fallback used over plain
// HTTP, where crypto.subtle does not exist.
func (s *Server) loginKey(w http.ResponseWriter, r *http.Request) {
	if s.LoginCrypto == nil {
		fail(w, http.StatusInternalServerError, "internal", "login encryption is not configured")
		return
	}
	ch, err := s.LoginCrypto.NewChallenge()
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	ok(w, map[string]any{
		"key":       s.LoginCrypto.PublicKeyB64(),
		"n":         s.LoginCrypto.ModulusHex(),
		"e":         s.LoginCrypto.Exponent(),
		"challenge": ch,
	})
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
	if s.LoginCrypto == nil {
		fail(w, http.StatusInternalServerError, "internal", "login encryption is not configured")
		return
	}
	if b.Enc == "" {
		fail(w, http.StatusBadRequest, "encryption_required", "the login password must be sent encrypted")
		return
	}
	password, err := s.LoginCrypto.Decrypt(b.Enc)
	if err != nil {
		// No credential was checked, so this is not a failed login attempt: the
		// rate limiter is left alone and the client (a stale challenge, a key
		// fetched before a restart) is told to retry instead of being locked out.
		fail(w, http.StatusBadRequest, "bad_login_payload", "could not decrypt the login payload, please retry")
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
	if !auth.VerifyPassword(password, u.PasswordHash, u.Salt) {
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
