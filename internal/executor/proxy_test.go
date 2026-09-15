package executor

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeProxy is a minimal forward proxy: it records the absolute target URLs it
// was asked for and answers everything itself, so a test can prove that a
// request went *through* it rather than straight to the target.
type fakeProxy struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen []string
	body string
	// redirectTo, when set, makes a target path ending in /redirect answer with a
	// 302 to that location — the stand-in for "the proxy follows a redirect".
	redirectTo string
}

func newFakeProxy(t *testing.T) *fakeProxy {
	t.Helper()
	p := &fakeProxy{body: "via proxy"}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.seen = append(p.seen, r.URL.String())
		loc := p.redirectTo
		p.mu.Unlock()
		if loc != "" && strings.HasSuffix(r.URL.Path, "/redirect") {
			http.Redirect(w, r, loc, http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, p.body)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeProxy) requests() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.seen...)
}

func TestExecuteThroughProxy(t *testing.T) {
	proxy := newFakeProxy(t)
	ex := NewExecutor(5 * time.Second)

	// The target host is not resolvable at all: with a proxy the instance must not
	// try, because the proxy is the one that resolves and reaches it.
	out, err := ex.Execute(context.Background(), In{
		Method:   "GET",
		URL:      "http://only-the-proxy-knows.invalid/thing?q=1",
		ProxyURL: proxy.srv.URL,
		Timeout:  5 * time.Second,
	}, mustWhitelist(t, "10.0.0.0/8"))
	if err != nil {
		t.Fatalf("Execute through proxy: %v", err)
	}
	if out.Body != "via proxy" || out.Status != http.StatusOK {
		t.Errorf("status/body = %d/%q, want 200/%q", out.Status, out.Body, "via proxy")
	}
	seen := proxy.requests()
	if len(seen) != 1 || !strings.Contains(seen[0], "only-the-proxy-knows.invalid/thing") {
		t.Fatalf("proxy saw %v, want one absolute URL for the target", seen)
	}
}

func TestExecuteWithoutProxyDialsDirectly(t *testing.T) {
	proxy := newFakeProxy(t)
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "direct")
	}))
	defer direct.Close()

	ex := NewExecutor(5 * time.Second)
	out, err := ex.Execute(context.Background(), In{
		Method: "GET", URL: direct.URL, Timeout: 5 * time.Second,
	}, mustWhitelist(t, "127.0.0.0/8"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.Body != "direct" {
		t.Errorf("body = %q, want the direct server's %q", out.Body, "direct")
	}
	if seen := proxy.requests(); len(seen) != 0 {
		t.Errorf("a request without ProxyURL went through the proxy: %v", seen)
	}
}

func TestExecuteThroughProxyStillRejectsNonHTTPSchemes(t *testing.T) {
	proxy := newFakeProxy(t)
	ex := NewExecutor(5 * time.Second)

	for _, target := range []string{"file:///etc/passwd", "gopher://10.0.0.1/", "dict://10.0.0.1:2628/", "http:///x"} {
		_, err := ex.Execute(context.Background(), In{
			Method: "GET", URL: target, ProxyURL: proxy.srv.URL, Timeout: 2 * time.Second,
		}, mustWhitelist(t, "10.0.0.0/8"))
		if !errors.Is(err, ErrSSRF) {
			t.Errorf("Execute(%q) through proxy error = %v, want ErrSSRF", target, err)
		}
	}
	if seen := proxy.requests(); len(seen) != 0 {
		t.Errorf("a rejected target reached the proxy: %v", seen)
	}
}

// A proxied request re-checks every redirect hop with the same policy, so a
// redirect cannot smuggle in a target the entry URL was not allowed to reach.
func TestExecuteThroughProxyRevalidatesRedirectHops(t *testing.T) {
	ex := NewExecutor(5 * time.Second)

	proxy := newFakeProxy(t)
	proxy.redirectTo = "file:///etc/passwd"
	_, err := ex.Execute(context.Background(), In{
		Method: "GET", URL: "http://target.invalid/redirect", ProxyURL: proxy.srv.URL,
		Follow: true, Timeout: 2 * time.Second,
	}, mustWhitelist(t, "10.0.0.0/8"))
	if !errors.Is(err, ErrSSRF) {
		t.Fatalf("redirect to a non-http scheme = %v, want ErrSSRF", err)
	}

	// The same hop is fine when the redirect stays on http(s): the proxy is the
	// one that dials it, so a host this instance cannot resolve is acceptable.
	ok := newFakeProxy(t)
	ok.redirectTo = "http://elsewhere.invalid/final"
	out, err := ex.Execute(context.Background(), In{
		Method: "GET", URL: "http://target.invalid/redirect", ProxyURL: ok.srv.URL,
		Follow: true, Timeout: 5 * time.Second,
	}, mustWhitelist(t, "10.0.0.0/8"))
	if err != nil {
		t.Fatalf("redirect within http(s) through the proxy: %v", err)
	}
	if out.Status != http.StatusOK || out.Body != "via proxy" {
		t.Errorf("status/body = %d/%q, want the redirected 200", out.Status, out.Body)
	}
}

func TestExecuteRejectsUnusableProxyURL(t *testing.T) {
	ex := NewExecutor(5 * time.Second)
	for _, proxyURL := range []string{"ftp://10.0.0.1:21", "://nope", "http://"} {
		_, err := ex.Execute(context.Background(), In{
			Method: "GET", URL: "http://10.0.0.1/x", ProxyURL: proxyURL, Timeout: 2 * time.Second,
		}, mustWhitelist(t, "10.0.0.0/8"))
		if err == nil {
			t.Errorf("Execute with ProxyURL %q succeeded, want an error", proxyURL)
		}
	}
}

// Proxy transports are cached per URL: repeated requests must reuse one pool.
func TestProxyTransportsAreCached(t *testing.T) {
	ex := NewExecutor(5 * time.Second)
	first, err := ex.transportFor("http://10.0.0.1:3128")
	if err != nil {
		t.Fatalf("transportFor: %v", err)
	}
	second, err := ex.transportFor("http://10.0.0.1:3128")
	if err != nil {
		t.Fatalf("transportFor (second): %v", err)
	}
	if first != second {
		t.Error("transportFor built a new transport for the same proxy URL")
	}
	direct, err := ex.transportFor("")
	if err != nil {
		t.Fatalf("transportFor(\"\"): %v", err)
	}
	if direct != ex.transport {
		t.Error("an empty proxy URL must return the shared direct transport")
	}
}
