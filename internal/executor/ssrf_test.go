package executor

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mustWhitelist(t *testing.T, s string) whitelist {
	t.Helper()
	wl, err := ParseWhitelist(s)
	if err != nil {
		t.Fatalf("ParseWhitelist(%q): %v", s, err)
	}
	return wl
}

func TestParseWhitelist(t *testing.T) {
	parsed, err := ParseWhitelist(" 10.0.0.0/8 , 192.168.0.0/16 ,")
	if err != nil {
		t.Fatalf("ParseWhitelist: %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("parsed %d CIDRs, want 2", len(parsed))
	}
	wl := whitelist(parsed)
	for _, allowed := range []string{"10.1.2.3", "192.168.5.5"} {
		if !wl.contains(net.ParseIP(allowed)) {
			t.Errorf("%s should be inside the whitelist", allowed)
		}
	}
	if wl.contains(net.ParseIP("8.8.8.8")) {
		t.Error("8.8.8.8 should be outside the whitelist")
	}

	if _, err := ParseWhitelist("10.0.0.0/8,not-a-cidr"); err == nil {
		t.Error("ParseWhitelist accepted an invalid CIDR")
	}
	if wl, err := ParseWhitelist(""); err != nil || len(wl) != 0 {
		t.Errorf("ParseWhitelist(\"\") = (%v, %v), want an empty list and no error", wl, err)
	}
}

func TestCheckTarget(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		wl      string
		wantErr bool
	}{
		{"private ip allowed", "http://10.1.2.3/api", "10.0.0.0/8", false},
		{"loopback allowed", "http://127.0.0.1:8080/api", "127.0.0.0/8", false},
		{"public ip blocked", "http://8.8.8.8/", "10.0.0.0/8", true},
		{"cloud metadata blocked", "http://169.254.169.254/latest/meta-data/", "10.0.0.0/8", true},
		{"ipv6 outside blocked", "http://[fd00::1]/", "10.0.0.0/8", true},
		{"scheme file blocked", "file:///etc/passwd", "10.0.0.0/8", true},
		{"scheme ftp blocked", "ftp://10.1.2.3/x", "10.0.0.0/8", true},
		{"schemeless blocked", "10.1.2.3:8080/x", "10.0.0.0/8", true},
		{"missing host blocked", "http:///x", "10.0.0.0/8", true},
		{"hostname outside blocked", "http://localhost:9/x", "10.0.0.0/8", true},
		{"hostname inside allowed", "http://localhost:9/x", "127.0.0.0/8,::1/128", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkTarget(context.Background(), tc.url, mustWhitelist(t, tc.wl))
			if !tc.wantErr {
				if err != nil {
					if strings.Contains(err.Error(), "dns ") {
						t.Skipf("hostname did not resolve in this environment: %v", err)
					}
					t.Fatalf("checkTarget(%q) = %v, want nil", tc.url, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("checkTarget(%q) = nil, want an SSRF error", tc.url)
			}
			if !errors.Is(err, ErrSSRF) {
				t.Errorf("checkTarget(%q) = %v, want an ErrSSRF-wrapped error", tc.url, err)
			}
		})
	}
}

func TestExecuteBlocksNonWhitelistedTarget(t *testing.T) {
	ex := NewExecutor(5 * time.Second)
	_, err := ex.Execute(context.Background(), In{
		Method:  "GET",
		URL:     "http://169.254.169.254/latest/meta-data/",
		Timeout: 2 * time.Second,
	}, mustWhitelist(t, "10.0.0.0/8"))
	if !errors.Is(err, ErrSSRF) {
		t.Fatalf("Execute error = %v, want an ErrSSRF-wrapped error", err)
	}
}

func TestExecuteRejectsDisallowedScheme(t *testing.T) {
	ex := NewExecutor(5 * time.Second)
	for _, target := range []string{"file:///etc/passwd", "gopher://10.0.0.1/", "dict://10.0.0.1:2628/"} {
		if _, err := ex.Execute(context.Background(), In{Method: "GET", URL: target},
			mustWhitelist(t, "10.0.0.0/8")); !errors.Is(err, ErrSSRF) {
			t.Errorf("Execute(%q) error = %v, want ErrSSRF", target, err)
		}
	}
}

func TestExecuteSendsResolvedRequestAndCapturesResponse(t *testing.T) {
	var (
		gotMethod string
		gotHeader string
		gotQuery  string
		gotBody   string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotHeader = r.Header.Get("X-Test")
		gotQuery = r.URL.Query().Get("q")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("X-Reply", "yes")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "hello")
	}))
	defer srv.Close()

	ex := NewExecutor(5 * time.Second)
	out, err := ex.Execute(context.Background(), In{
		Method:   "post", // must be upper-cased
		URL:      srv.URL + "/thing",
		Headers:  map[string]string{"X-Test": "v"},
		Query:    [][2]string{{"q", "1"}},
		BodyType: "json",
		Body:     `{"a":1}`,
		Timeout:  5 * time.Second,
	}, mustWhitelist(t, "127.0.0.0/8"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.Status != http.StatusCreated {
		t.Errorf("status = %d, want 201", out.Status)
	}
	if out.Body != "hello" {
		t.Errorf("body = %q, want %q", out.Body, "hello")
	}
	if v := out.Headers["X-Reply"]; len(v) != 1 || v[0] != "yes" {
		t.Errorf("X-Reply = %v, want [yes]", v)
	}
	if !strings.Contains(out.FinalURL, "/thing") || !strings.Contains(out.FinalURL, "q=1") {
		t.Errorf("FinalURL = %q, want the request path and query", out.FinalURL)
	}
	if gotMethod != "POST" || gotHeader != "v" || gotQuery != "1" || gotBody != `{"a":1}` {
		t.Errorf("upstream saw method=%q header=%q query=%q body=%q", gotMethod, gotHeader, gotQuery, gotBody)
	}
	if out.Truncated {
		t.Error("small response reported as truncated")
	}
}

func newRedirectServer(t *testing.T, target string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusFound)
	})
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestExecuteDoesNotFollowRedirectsByDefault(t *testing.T) {
	srv := newRedirectServer(t, "/ok")
	ex := NewExecutor(5 * time.Second)

	out, err := ex.Execute(context.Background(), In{
		Method: "GET", URL: srv.URL + "/start", Timeout: 5 * time.Second,
		Follow: false,
	}, mustWhitelist(t, "127.0.0.0/8"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.Status != http.StatusFound {
		t.Errorf("status = %d, want the 302 returned as-is", out.Status)
	}
	if !strings.HasSuffix(out.FinalURL, "/start") {
		t.Errorf("FinalURL = %q, want the request to stay on /start", out.FinalURL)
	}
}

func TestExecuteFollowsWhitelistedRedirectWhenEnabled(t *testing.T) {
	srv := newRedirectServer(t, "/ok")
	ex := NewExecutor(5 * time.Second)

	out, err := ex.Execute(context.Background(), In{
		Method: "GET", URL: srv.URL + "/start", Timeout: 5 * time.Second,
		Follow: true,
	}, mustWhitelist(t, "127.0.0.0/8"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.Status != http.StatusOK || out.Body != "ok" {
		t.Errorf("status/body = %d/%q, want 200/ok", out.Status, out.Body)
	}
	if !strings.HasSuffix(out.FinalURL, "/ok") {
		t.Errorf("FinalURL = %q, want the redirect to be followed", out.FinalURL)
	}
}

func TestExecuteRevalidatesRedirectTarget(t *testing.T) {
	// The redirect target is outside the whitelist, so the hop must be blocked
	// before any connection is attempted.
	srv := newRedirectServer(t, "http://8.8.8.8/")
	ex := NewExecutor(5 * time.Second)

	_, err := ex.Execute(context.Background(), In{
		Method: "GET", URL: srv.URL + "/start", Timeout: 2 * time.Second,
		Follow: true,
	}, mustWhitelist(t, "127.0.0.0/8"))
	if !errors.Is(err, ErrSSRF) {
		t.Fatalf("Execute error = %v, want the redirect hop to be blocked as SSRF", err)
	}
}

func TestHistoryBodyTruncates(t *testing.T) {
	long := &Out{Body: strings.Repeat("a", historyBodyBytes+512)}
	if got := long.HistoryBody(); len(got) != historyBodyBytes {
		t.Errorf("HistoryBody length = %d, want %d", len(got), historyBodyBytes)
	}
	short := &Out{Body: "abc"}
	if got := short.HistoryBody(); got != "abc" {
		t.Errorf("HistoryBody = %q, want the body unchanged", got)
	}
}
