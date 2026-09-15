package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeProxy answers every request itself and records the absolute target URLs,
// which is how these tests tell "went through the proxy" from "went direct".
type fakeProxy struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen []string
}

func newFakeProxy(t *testing.T) *fakeProxy {
	t.Helper()
	p := &fakeProxy{}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.seen = append(p.seen, r.URL.String())
		p.mu.Unlock()
		_, _ = io.WriteString(w, "via proxy")
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeProxy) requests() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.seen...)
}

func (p *fakeProxy) hit() bool { return len(p.requests()) > 0 }

// ---- proxy setting ----

func TestSettingsProxyURLValidation(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))

	// Every GET value must be PUTtable back verbatim (the UI saves the form as-is).
	code, resp, raw := ts.call("GET", "/api/settings", admin, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /api/settings = %d (%s)", code, raw)
	}
	var defaults map[string]string
	resp.decode(t, &defaults)
	if v, ok := defaults["proxy_url"]; !ok || v != "" {
		t.Errorf("proxy_url default = %q (present=%v), want an empty string = direct", v, ok)
	}
	if code, _, raw := ts.call("PUT", "/api/settings", admin, defaults); code != http.StatusOK {
		t.Fatalf("saving the defaults back = %d, want 200 (%s)", code, raw)
	}

	valid := []string{"http://10.0.0.9:3128", "https://proxy.corp:8443", "http://user:pw@10.0.0.9:3128"}
	for _, v := range valid {
		if code, _, raw := ts.call("PUT", "/api/settings", admin, map[string]string{"proxy_url": v}); code != http.StatusOK {
			t.Errorf("PUT proxy_url=%q = %d, want 200 (%s)", v, code, raw)
		}
	}

	// socks5 is not implemented yet, and a bare host:port is not a URL: both must
	// be refused instead of silently turning into a broken send.
	invalid := []string{"socks5://10.0.0.9:1080", "10.0.0.9:3128", "ftp://10.0.0.9:21", "http://"}
	for _, v := range invalid {
		code, resp, raw := ts.call("PUT", "/api/settings", admin, map[string]string{"proxy_url": v})
		if code != http.StatusBadRequest {
			t.Errorf("PUT proxy_url=%q = %d, want 400 (%s)", v, code, raw)
			continue
		}
		if resp.Error == nil || resp.Error.Code != "bad_request" {
			t.Errorf("PUT proxy_url=%q error = %+v, want code bad_request", v, resp.Error)
		}
	}

	// The rejected writes did not land, and an empty value clears the setting.
	if code, _, raw := ts.call("PUT", "/api/settings", admin, map[string]string{"proxy_url": ""}); code != http.StatusOK {
		t.Fatalf("clearing proxy_url = %d (%s)", code, raw)
	}
	code, resp, raw = ts.call("GET", "/api/settings", admin, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /api/settings = %d (%s)", code, raw)
	}
	var got map[string]string
	resp.decode(t, &got)
	if got["proxy_url"] != "" {
		t.Errorf("proxy_url = %q after clearing, want empty", got["proxy_url"])
	}
}

// ---- execution ----

func TestExecuteUseProxyWithoutConfiguredProxy(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))

	code, resp, raw := ts.call("POST", "/api/execute", admin, map[string]any{
		"ad_hoc": map[string]any{"method": "GET", "url": "http://10.0.0.1/x", "use_proxy": true},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("execute with use_proxy and no proxy_url = %d, want 400 (%s)", code, raw)
	}
	if resp.Error == nil || resp.Error.Code != "proxy_not_configured" {
		t.Errorf("error = %+v, want code proxy_not_configured", resp.Error)
	}
}

func TestExecuteRoutesThroughTheConfiguredProxy(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))
	proxy := newFakeProxy(t)

	if code, _, raw := ts.call("PUT", "/api/settings", admin,
		map[string]string{"proxy_url": proxy.srv.URL}); code != http.StatusOK {
		t.Fatalf("configure proxy_url = %d (%s)", code, raw)
	}

	// The host does not resolve here at all: only the proxy can reach it.
	const target = "http://only-the-proxy-knows.invalid/thing"
	code, resp, raw := ts.call("POST", "/api/execute", admin, map[string]any{
		"ad_hoc": map[string]any{"method": "GET", "url": target, "use_proxy": true},
	})
	if code != http.StatusOK {
		t.Fatalf("proxied execute = %d (%s)", code, raw)
	}
	var out struct {
		Body    string `json:"body"`
		Proxied bool   `json:"proxied"`
	}
	resp.decode(t, &out)
	if out.Body != "via proxy" {
		t.Errorf("body = %q, want the proxy's response", out.Body)
	}
	if !out.Proxied {
		t.Error("response.proxied = false, want true")
	}
	seen := proxy.requests()
	if len(seen) != 1 || !strings.Contains(seen[0], "only-the-proxy-knows.invalid/thing") {
		t.Fatalf("proxy saw %v, want one absolute URL for the target", seen)
	}

	// The same target without the flag is a direct request and stays blocked by
	// the SSRF whitelist, which is what makes the flag meaningful.
	before := len(proxy.requests())
	code, resp, raw = ts.call("POST", "/api/execute", admin, map[string]any{
		"ad_hoc": map[string]any{"method": "GET", "url": target},
	})
	if code != http.StatusUnavailableForLegalReasons {
		t.Errorf("direct execute of the same target = %d, want 451 (%s)", code, raw)
	}
	if resp.Error == nil || resp.Error.Code != "ssrf_blocked" {
		t.Errorf("error = %+v, want code ssrf_blocked", resp.Error)
	}
	if len(proxy.requests()) != before {
		t.Error("a request without use_proxy reached the proxy")
	}
	if out.Proxied == false {
		t.Error("proxied flag missing on the direct path check")
	}
}

func TestStoredRequestUseProxyRoundTrips(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))
	proxy := newFakeProxy(t)
	colID := ts.createCollection(admin, "proxied", false)

	if code, _, raw := ts.call("PUT", "/api/settings", admin,
		map[string]string{"proxy_url": proxy.srv.URL}); code != http.StatusOK {
		t.Fatalf("configure proxy_url = %d (%s)", code, raw)
	}

	const target = "http://only-the-proxy-knows.invalid/thing"
	code, resp, raw := ts.call("POST", "/api/requests", admin, map[string]any{
		"collection_id": colID,
		"name":          "through-proxy",
		"method":        "GET",
		"url":           target,
		"use_proxy":     true,
	})
	if code != http.StatusCreated {
		t.Fatalf("create request = %d (%s)", code, raw)
	}
	var created struct {
		ID int64 `json:"id"`
	}
	resp.decode(t, &created)

	// The flag is persisted (not just echoed) and survives a reload.
	var stored int
	if err := ts.db.QueryRow("SELECT use_proxy FROM requests WHERE id = ?", created.ID).Scan(&stored); err != nil {
		t.Fatalf("read use_proxy: %v", err)
	}
	if stored != 1 {
		t.Errorf("requests.use_proxy = %d, want 1", stored)
	}
	code, resp, raw = ts.call("GET", "/api/requests/"+idStr(created.ID), admin, nil)
	if code != http.StatusOK {
		t.Fatalf("get request = %d (%s)", code, raw)
	}
	var fetched struct {
		UseProxy bool `json:"use_proxy"`
	}
	resp.decode(t, &fetched)
	if !fetched.UseProxy {
		t.Error("GET /api/requests/{id} dropped use_proxy")
	}

	// Executing the stored request goes through the proxy without any ad-hoc flag.
	code, resp, raw = ts.call("POST", "/api/execute", admin, map[string]any{"request_id": created.ID})
	if code != http.StatusOK {
		t.Fatalf("execute the stored request = %d (%s)", code, raw)
	}
	var out struct {
		Proxied bool `json:"proxied"`
	}
	resp.decode(t, &out)
	if !out.Proxied || !proxy.hit() {
		t.Errorf("stored use_proxy was ignored: proxied=%v proxyHit=%v", out.Proxied, proxy.hit())
	}

	// Turning it off persists too, and sends go direct again (blocked here).
	code, _, raw = ts.call("PUT", "/api/requests/"+idStr(created.ID), admin, map[string]any{
		"name": "through-proxy", "method": "GET", "url": target, "use_proxy": false,
	})
	if code != http.StatusOK {
		t.Fatalf("update request = %d (%s)", code, raw)
	}
	if err := ts.db.QueryRow("SELECT use_proxy FROM requests WHERE id = ?", created.ID).Scan(&stored); err != nil {
		t.Fatalf("read use_proxy: %v", err)
	}
	if stored != 0 {
		t.Errorf("requests.use_proxy = %d after clearing it, want 0", stored)
	}
}

// ---- request deletion ----

// Deleting a request is admin-only; editing one is not, so the boundary sits
// exactly on delete.
func TestDeleteRequestIsAdminOnly(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))
	bob := ts.cookie(ts.createUser("bob", "user", loginPassword))

	colID := ts.createCollection(bob, "bob-col", false)
	reqID := mustRequest(t, ts, bob, map[string]any{
		"collection_id": colID, "name": "bob-req", "method": "GET", "url": "http://10.0.0.1/x",
	})

	// The owner may still edit it...
	if code, _, raw := ts.call("PUT", "/api/requests/"+idStr(reqID), bob, map[string]any{
		"name": "bob-req", "method": "GET", "url": "http://10.0.0.1/y",
	}); code != http.StatusOK {
		t.Fatalf("owner update = %d, want 200 (%s)", code, raw)
	}
	// ...but not delete it, not even an admin's global request.
	code, resp, raw := ts.call("DELETE", "/api/requests/"+idStr(reqID), bob, nil)
	if code != http.StatusForbidden {
		t.Fatalf("user delete = %d, want 403 (%s)", code, raw)
	}
	if resp.Error == nil || resp.Error.Code != "forbidden" {
		t.Errorf("error = %+v, want code forbidden", resp.Error)
	}
	if code, _, _ := ts.call("GET", "/api/requests/"+idStr(reqID), bob, nil); code != http.StatusOK {
		t.Fatalf("the request survived the refused delete? GET = %d", code)
	}

	if code, _, raw := ts.call("DELETE", "/api/requests/"+idStr(reqID), admin, nil); code != http.StatusOK {
		t.Fatalf("admin delete = %d, want 200 (%s)", code, raw)
	}
	if code, _, _ := ts.call("GET", "/api/requests/"+idStr(reqID), admin, nil); code != http.StatusNotFound {
		t.Errorf("GET after delete = %d, want 404", code)
	}
	if !ts.auditedAction("request.delete") {
		t.Errorf("the delete was not audited: %v", ts.audits)
	}

	// An anonymous caller gets 401, and a missing id 404 -- not a crash.
	if code, _, _ := ts.call("DELETE", "/api/requests/"+idStr(reqID), nil, nil); code != http.StatusUnauthorized {
		t.Errorf("anonymous delete = %d, want 401", code)
	}
	if code, _, _ := ts.call("DELETE", "/api/requests/999999", admin, nil); code != http.StatusNotFound {
		t.Errorf("delete of a missing request = %d, want 404", code)
	}
}
