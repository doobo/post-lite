package httpapi

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"postlite/internal/executor"
)

// allowedSettings are the admin-manageable settings keys.
var allowedSettings = map[string]struct{}{
	"ssrf_whitelist": {},
	"exec_timeout":   {},
	"max_history":    {},
	"proxy_url":      {},
}

// parseTimeout accepts a Go duration string ("60s", "2m") or a bare number
// of seconds, and reports whether the value is usable.
func parseTimeout(v string) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d, true
	}
	if sec, err := strconv.Atoi(v); err == nil && sec > 0 {
		return time.Duration(sec) * time.Second, true
	}
	return 0, false
}

// validateSetting rejects values the consumers cannot parse, so a typo cannot
// silently disable SSRF protection or the execution timeout. An empty value is
// accepted and falls back to the configured default.
func validateSetting(key, value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	switch key {
	case "ssrf_whitelist":
		if _, err := executor.ParseWhitelist(value); err != nil {
			return err
		}
	case "exec_timeout":
		if _, ok := parseTimeout(value); !ok {
			return fmt.Errorf("exec_timeout must be a duration like 60s or 2m, got %q", value)
		}
	case "max_history":
		if n, err := strconv.Atoi(strings.TrimSpace(value)); err != nil || n <= 0 {
			return fmt.Errorf("max_history must be a positive integer, got %q", value)
		}
	case "proxy_url":
		// Only http/https: those are the two schemes the executor can dial, and
		// rejecting the rest here keeps a typo from failing at send time.
		u, err := url.Parse(strings.TrimSpace(value))
		if err != nil {
			return fmt.Errorf("proxy_url is not a valid URL: %v", err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("proxy_url must start with http:// or https://, got %q", value)
		}
		if u.Host == "" {
			return fmt.Errorf("proxy_url needs a host:port, got %q", value)
		}
	}
	return nil
}

// getSettings (admin): returns the manageable settings.
func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	if _, okd := s.requireAdmin(w, r); !okd {
		return
	}
	all, err := s.Store.Settings.All()
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	out := map[string]string{
		"ssrf_whitelist": s.settingOr("ssrf_whitelist", defaultWhitelist),
		"exec_timeout":   s.CFG.Timeout.String(),
		"max_history":    "1000",
		"proxy_url":      "", // empty = every request goes direct
	}
	for k := range out {
		if v, ok := all[k]; ok {
			out[k] = v
		}
	}
	ok(w, out)
}

// putSettings (admin): upserts allowed settings.
func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	admin, okd := s.requireAdmin(w, r)
	if !okd {
		return
	}
	var b map[string]string
	if !decodeBody(w, r, &b) {
		return
	}

	// Validate every key before writing any of them, so a single bad value
	// cannot leave the update half-applied.
	for k, v := range b {
		if _, allowed := allowedSettings[k]; !allowed {
			fail(w, http.StatusBadRequest, "bad_request", "key not allowed: "+k)
			return
		}
		if err := validateSetting(k, v); err != nil {
			fail(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
	}

	saved := []string{}
	for k, v := range b {
		if err := s.Store.Settings.Set(k, v); err != nil {
			fail(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		saved = append(saved, k)
		s.audit(admin.Username, "settings.put", k+"="+v)
	}
	ok(w, map[string]any{"saved": saved})
}
