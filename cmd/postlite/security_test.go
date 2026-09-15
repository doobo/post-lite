package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"postlite/internal/auth"
	"postlite/internal/config"
	"postlite/internal/crypto"
	"postlite/internal/db"
	"postlite/internal/executor"
	"postlite/internal/httpapi"
	"postlite/internal/repository"
)

// testSecretValue is the plaintext used everywhere below; no response, history
// row, or database column may ever contain it.
const testSecretValue = "correct-horse-battery-staple-42"

// apiResp is the unified {"ok":..} envelope.
type apiResp struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (r apiResp) decode(t *testing.T, v any) {
	t.Helper()
	if !r.OK {
		t.Fatalf("response not ok: %+v", r.Error)
	}
	if err := json.Unmarshal(r.Data, v); err != nil {
		t.Fatalf("decode data %s: %v", r.Data, err)
	}
}

// testRemoteAddr is the peer address used unless a test overrides it.
const testRemoteAddr = "192.0.2.1:1234"

// serverOption tweaks the configuration of a test server.
type serverOption func(*config.Config)

// withSecureCookie marks the session cookie Secure, as it is under TLS.
func withSecureCookie() serverOption {
	return func(c *config.Config) { c.SecureCookie = true }
}

// testServer runs a full postlite stack (real route table, real session
// middleware, real SQLite file, real vault) for one test.
type testServer struct {
	t       *testing.T
	db      *sql.DB
	store   *repository.Store
	vault   *crypto.Vault
	cfg     config.Config
	handler http.Handler
	audits  []string
}

func newTestServer(t *testing.T, opts ...serverOption) *testServer {
	t.Helper()

	sdb, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = sdb.Close() })

	vault, err := crypto.New(crypto.GenerateMasterKey())
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}

	cfg := config.Config{Timeout: 5 * time.Second, MaxHistory: 100}
	for _, opt := range opts {
		opt(&cfg)
	}
	store := repository.New(sdb)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httpapi.New(store, vault, executor.NewExecutor(cfg.Timeout), cfg, auth.NewRateLimiter())
	loginCrypto, err := auth.NewLoginCrypto()
	if err != nil {
		t.Fatalf("auth.NewLoginCrypto: %v", err)
	}
	srv.SetLoginCrypto(loginCrypto)
	srv.SetLog(logger)

	ts := &testServer{t: t, db: sdb, store: store, vault: vault, cfg: cfg}
	srv.SetAuditFunc(func(_, action, detail string) {
		ts.audits = append(ts.audits, action+" "+detail)
	})

	apiMux := http.NewServeMux()
	registerAPIRoutes(apiMux, srv)
	api := auth.Middleware(auth.SessionDeps{Sessions: store.Sessions, Users: store.Users})(apiMux)
	ts.handler = withRecover(api, logger)
	return ts
}

// callFrom issues a JSON request from a specific peer address and returns the
// raw recorder, so tests can inspect response headers and cookies.
func (ts *testServer) callFrom(method, path, remoteAddr string, cookie *http.Cookie, body any) *httptest.ResponseRecorder {
	ts.t.Helper()

	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			ts.t.Fatalf("marshal request body: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteAddr
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, req)
	return rec
}

// call issues a JSON request through the real mux + middleware.
func (ts *testServer) call(method, path string, cookie *http.Cookie, body any) (int, apiResp, string) {
	ts.t.Helper()

	rec := ts.callFrom(method, path, testRemoteAddr, cookie, body)
	raw := rec.Body.String()
	var resp apiResp
	// Non-JSON mux errors (404/405) leave the zero value in place.
	_ = json.Unmarshal([]byte(raw), &resp)
	return rec.Code, resp, raw
}

func (ts *testServer) createUser(username, role, password string) int64 {
	ts.t.Helper()
	hash, salt, err := auth.HashPassword(password)
	if err != nil {
		ts.t.Fatalf("HashPassword: %v", err)
	}
	id, err := ts.store.Users.Create(username, role, salt, hash)
	if err != nil {
		ts.t.Fatalf("create user %q: %v", username, err)
	}
	return id
}

// login writes a real session row and returns the matching cookie.
func (ts *testServer) login(userID int64, ttl time.Duration) *http.Cookie {
	ts.t.Helper()
	token, hash, err := auth.NewToken()
	if err != nil {
		ts.t.Fatalf("NewToken: %v", err)
	}
	if err := ts.store.Sessions.Create(hash, userID, ttl); err != nil {
		ts.t.Fatalf("session create: %v", err)
	}
	return &http.Cookie{Name: "session", Value: token}
}

func (ts *testServer) cookie(userID int64) *http.Cookie {
	return ts.login(userID, auth.SessionTTL)
}

func (ts *testServer) auditedAction(action string) bool {
	for _, a := range ts.audits {
		if strings.HasPrefix(a, action) {
			return true
		}
	}
	return false
}

func (ts *testServer) createCollection(cookie *http.Cookie, name string, global bool) int64 {
	ts.t.Helper()
	code, resp, raw := ts.call("POST", "/api/collections", cookie, map[string]any{"name": name, "global": global})
	if code != http.StatusCreated {
		ts.t.Fatalf("create collection %q = %d (%s)", name, code, raw)
	}
	var d struct {
		ID int64 `json:"id"`
	}
	resp.decode(ts.t, &d)
	return d.ID
}

func (ts *testServer) createRequest(cookie *http.Cookie, collectionID int64, name string) int64 {
	ts.t.Helper()
	code, resp, raw := ts.call("POST", "/api/requests", cookie, map[string]any{
		"collection_id": collectionID,
		"name":          name,
		"method":        "GET",
		"url":           "http://10.0.0.1/health",
	})
	if code != http.StatusCreated {
		ts.t.Fatalf("create request %q = %d (%s)", name, code, raw)
	}
	var d struct {
		ID int64 `json:"id"`
	}
	resp.decode(ts.t, &d)
	return d.ID
}

func idStr(n int64) string { return strconv.FormatInt(n, 10) }

// TestSecretIsWriteOnly pins the vault contract: values go in encrypted, no
// API returns a value, and only the in-process vault can decrypt.
func TestSecretIsWriteOnly(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", "pw"))
	user := ts.cookie(ts.createUser("user1", "user", "pw"))

	code, resp, raw := ts.call("POST", "/api/secrets", admin,
		map[string]any{"name": "api_key", "value": testSecretValue})
	if code != http.StatusCreated {
		t.Fatalf("create secret = %d (%s)", code, raw)
	}
	if strings.Contains(raw, testSecretValue) {
		t.Fatalf("create-secret response leaked the value: %s", raw)
	}
	var created struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	}
	resp.decode(t, &created)
	if created.ID == 0 || created.Name != "api_key" {
		t.Fatalf("create response = %+v, want an id and the name", created)
	}

	// Listing returns metadata only.
	code, resp, raw = ts.call("GET", "/api/secrets", admin, nil)
	if code != http.StatusOK {
		t.Fatalf("list secrets = %d (%s)", code, raw)
	}
	if strings.Contains(raw, testSecretValue) {
		t.Fatalf("list-secrets response leaked the value: %s", raw)
	}
	var metas []map[string]any
	resp.decode(t, &metas)
	if len(metas) != 1 {
		t.Fatalf("listed %d secrets, want 1", len(metas))
	}
	for _, m := range metas {
		for _, forbidden := range []string{"value", "ciphertext", "secret", "plaintext"} {
			if _, present := m[forbidden]; present {
				t.Errorf("secret metadata exposes %q: %v", forbidden, m)
			}
		}
	}

	// There is no read-value endpoint.
	code, _, raw = ts.call("GET", "/api/secrets/api_key", admin, nil)
	if code == http.StatusOK {
		t.Errorf("GET /api/secrets/api_key returned 200; secrets must be unreadable")
	}
	if strings.Contains(raw, testSecretValue) {
		t.Errorf("unknown route leaked the value: %s", raw)
	}

	// The stored form is ciphertext, and the vault can still decrypt it.
	var blob []byte
	if err := ts.db.QueryRow("SELECT ciphertext FROM secrets WHERE name = ?", "api_key").Scan(&blob); err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}
	if bytes.Contains(blob, []byte(testSecretValue)) {
		t.Fatal("the plaintext was found in the secrets table")
	}
	if got, ok := ts.vault.Lookup("api_key", func() ([]byte, error) { return blob, nil }); !ok || got != testSecretValue {
		t.Fatalf("vault lookup = (%q, %v), want the injected value", got, ok)
	}

	// Overwriting stays write-only and refreshes the vault cache.
	const second = "second-value"
	code, _, raw = ts.call("PUT", "/api/secrets/api_key", admin, map[string]any{"value": second})
	if code != http.StatusOK {
		t.Fatalf("update secret = %d (%s)", code, raw)
	}
	if strings.Contains(raw, second) {
		t.Fatalf("update-secret response leaked the value: %s", raw)
	}
	if err := ts.db.QueryRow("SELECT ciphertext FROM secrets WHERE name = ?", "api_key").Scan(&blob); err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}
	if got, ok := ts.vault.Lookup("api_key", func() ([]byte, error) { return blob, nil }); !ok || got != second {
		t.Fatalf("vault lookup after overwrite = (%q, %v), want %q", got, ok, second)
	}

	// Secrets are admin-only.
	if code, _, _ := ts.call("GET", "/api/secrets", user, nil); code != http.StatusForbidden {
		t.Errorf("non-admin list secrets = %d, want 403", code)
	}
	if code, _, _ := ts.call("POST", "/api/secrets", user, map[string]any{"name": "nope", "value": "x"}); code != http.StatusForbidden {
		t.Errorf("non-admin create secret = %d, want 403", code)
	}
	if code, _, _ := ts.call("GET", "/api/secrets", nil, nil); code != http.StatusUnauthorized {
		t.Errorf("anonymous list secrets = %d, want 401", code)
	}
}

// TestCrossUserResourcesAreIsolated pins the repository-level owner filtering.
func TestCrossUserResourcesAreIsolated(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", "pw"))
	alice := ts.cookie(ts.createUser("alice", "user", "pw"))
	bob := ts.cookie(ts.createUser("bob", "user", "pw"))

	aliceCol := ts.createCollection(alice, "alice-col", false)
	ts.createCollection(bob, "bob-col", false)

	path := "/api/collections/" + idStr(aliceCol)
	if code, _, _ := ts.call("GET", path, bob, nil); code != http.StatusForbidden {
		t.Errorf("bob reading alice's collection = %d, want 403", code)
	}
	if code, _, _ := ts.call("GET", path, alice, nil); code != http.StatusOK {
		t.Errorf("alice reading her own collection = %d, want 200", code)
	}
	if code, _, _ := ts.call("GET", path, admin, nil); code != http.StatusOK {
		t.Errorf("admin reading a user collection = %d, want 200", code)
	}
	if code, _, _ := ts.call("PUT", path, bob, map[string]any{"name": "hijacked"}); code != http.StatusForbidden {
		t.Errorf("bob renaming alice's collection = %d, want 403", code)
	}
	if code, _, _ := ts.call("DELETE", path, bob, nil); code != http.StatusForbidden {
		t.Errorf("bob deleting alice's collection = %d, want 403", code)
	}

	// Bob's listing must not mention alice's collection.
	code, resp, raw := ts.call("GET", "/api/collections", bob, nil)
	if code != http.StatusOK {
		t.Fatalf("bob listing collections = %d (%s)", code, raw)
	}
	var cols []struct {
		ID int64 `json:"id"`
	}
	resp.decode(t, &cols)
	for _, c := range cols {
		if c.ID == aliceCol {
			t.Fatalf("bob can see alice's collection %d: %s", c.ID, raw)
		}
	}

	aliceReq := ts.createRequest(alice, aliceCol, "alice-req")
	reqPath := "/api/requests/" + idStr(aliceReq)
	if code, _, _ := ts.call("GET", reqPath, bob, nil); code != http.StatusForbidden {
		t.Errorf("bob reading alice's request = %d, want 403", code)
	}
	if code, _, _ := ts.call("PUT", reqPath, bob, map[string]any{"method": "GET", "url": "http://10.0.0.1/x"}); code != http.StatusForbidden {
		t.Errorf("bob updating alice's request = %d, want 403", code)
	}
	if code, _, _ := ts.call("DELETE", reqPath, bob, nil); code != http.StatusForbidden {
		t.Errorf("bob deleting alice's request = %d, want 403", code)
	}
	if code, _, _ := ts.call("GET", "/api/requests?collection_id="+idStr(aliceCol), bob, nil); code != http.StatusForbidden {
		t.Errorf("bob listing alice's requests = %d, want 403", code)
	}
	if code, _, _ := ts.call("POST", "/api/execute", bob, map[string]any{"request_id": aliceReq}); code != http.StatusForbidden {
		t.Errorf("bob executing alice's request = %d, want 403", code)
	}

	// Global (admin-owned) resources are shared, but only admins create them.
	globalCol := ts.createCollection(admin, "global-col", true)
	if code, _, _ := ts.call("GET", "/api/collections/"+idStr(globalCol), bob, nil); code != http.StatusOK {
		t.Errorf("bob reading a global collection = %d, want 200", code)
	}
	if code, _, _ := ts.call("POST", "/api/collections", bob, map[string]any{"name": "nope", "global": true}); code != http.StatusForbidden {
		t.Errorf("non-admin creating a global collection = %d, want 403", code)
	}

	// Unauthenticated access is rejected everywhere.
	for _, p := range []string{
		"/api/collections",
		"/api/requests?collection_id=" + idStr(aliceCol),
		"/api/environments",
		"/api/history",
		"/api/settings",
		"/api/users",
	} {
		if code, _, _ := ts.call("GET", p, nil, nil); code != http.StatusUnauthorized {
			t.Errorf("anonymous GET %s = %d, want 401", p, code)
		}
	}
	// Non-admins cannot reach admin-only endpoints.
	for _, p := range []string{"/api/users", "/api/settings"} {
		if code, _, _ := ts.call("GET", p, bob, nil); code != http.StatusForbidden {
			t.Errorf("non-admin GET %s = %d, want 403", p, code)
		}
	}
}

func TestSessionsMustBeLive(t *testing.T) {
	ts := newTestServer(t)
	uid := ts.createUser("user1", "user", "pw")

	live := ts.cookie(uid)
	if code, _, _ := ts.call("GET", "/api/auth/me", live, nil); code != http.StatusOK {
		t.Fatalf("live session = %d, want 200", code)
	}

	expired := ts.login(uid, -time.Minute)
	if code, _, _ := ts.call("GET", "/api/auth/me", expired, nil); code != http.StatusUnauthorized {
		t.Errorf("expired session = %d, want 401", code)
	}

	if err := ts.store.Users.SetEnabled(uid, false); err != nil {
		t.Fatalf("disable user: %v", err)
	}
	if code, _, _ := ts.call("GET", "/api/auth/me", live, nil); code != http.StatusUnauthorized {
		t.Errorf("disabled user with a live session = %d, want 401", code)
	}

	bogus := &http.Cookie{Name: "session", Value: "not-a-real-token"}
	if code, _, _ := ts.call("GET", "/api/auth/me", bogus, nil); code != http.StatusUnauthorized {
		t.Errorf("forged session cookie = %d, want 401", code)
	}
}

// TestExecuteBlocksSSRF pins the executor's CIDR policy at the API boundary.
func TestExecuteBlocksSSRF(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", "pw"))

	for _, target := range []string{
		"http://8.8.8.8/",
		"http://169.254.169.254/latest/meta-data/",
		"http://[fd00::1]/",
		"file:///etc/passwd",
	} {
		code, resp, raw := ts.call("POST", "/api/execute", admin,
			map[string]any{"ad_hoc": map[string]any{"method": "GET", "url": target}})
		if code != http.StatusUnavailableForLegalReasons {
			t.Errorf("execute %s = %d, want 451 (%s)", target, code, raw)
			continue
		}
		if resp.Error == nil || resp.Error.Code != "ssrf_blocked" {
			t.Errorf("execute %s error = %+v, want code ssrf_blocked", target, resp.Error)
		}
	}
	if !ts.auditedAction("execute.ssrf_blocked") {
		t.Errorf("blocked requests were not audited: %v", ts.audits)
	}

	// An unresolved placeholder never reaches the network.
	code, resp, raw := ts.call("POST", "/api/execute", admin,
		map[string]any{"ad_hoc": map[string]any{"method": "GET", "url": "http://{{missing_host}}/x"}})
	if code != http.StatusBadRequest {
		t.Fatalf("execute with an unresolved placeholder = %d (%s)", code, raw)
	}
	if resp.Error == nil || resp.Error.Code != "unresolved_variable" {
		t.Errorf("error = %+v, want code unresolved_variable", resp.Error)
	}
}

// TestExecuteRedactsInjectedSecret is the end-to-end redaction test: the
// secret is injected into the URL and a header, echoed back by the upstream,
// and must be masked in the response, the history snapshot and the database.
func TestExecuteRedactsInjectedSecret(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", "pw"))

	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sid="+testSecretValue)
		w.Header().Set("X-Echo", r.Header.Get("Authorization"))
		body := `{"token":"` + r.Header.Get("Authorization") + `","q":"` + r.URL.RawQuery + `"}`
		_, _ = io.WriteString(w, body)
	}))
	defer echo.Close()

	code, _, raw := ts.call("POST", "/api/secrets", admin,
		map[string]any{"name": "token", "value": testSecretValue})
	if code != http.StatusCreated {
		t.Fatalf("create secret = %d (%s)", code, raw)
	}

	code, resp, raw := ts.call("POST", "/api/execute", admin, map[string]any{
		"ad_hoc": map[string]any{
			"method":  "GET",
			"url":     echo.URL + "/echo?key={{sec.token}}",
			"headers": map[string]string{"Authorization": "Bearer {{sec.token}}"},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("execute = %d (%s)", code, raw)
	}
	if strings.Contains(raw, testSecretValue) {
		t.Fatalf("execute response leaked the secret: %s", raw)
	}
	var result struct {
		Status   int                 `json:"status"`
		Body     string              `json:"body"`
		FinalURL string              `json:"final_url"`
		Headers  map[string][]string `json:"headers"`
	}
	resp.decode(t, &result)
	if result.Status != http.StatusOK {
		t.Errorf("upstream status = %d, want 200", result.Status)
	}
	if !strings.Contains(result.Body, "***") {
		t.Errorf("response body was not redacted: %q", result.Body)
	}
	if got := result.Headers["Set-Cookie"]; len(got) != 1 || got[0] != "***" {
		t.Errorf("Set-Cookie = %v, want [***]", got)
	}
	if strings.Contains(result.FinalURL, testSecretValue) {
		t.Errorf("final_url leaked the secret: %q", result.FinalURL)
	}

	// History must store only the redacted snapshot.
	code, resp, raw = ts.call("GET", "/api/history", admin, nil)
	if code != http.StatusOK {
		t.Fatalf("list history = %d (%s)", code, raw)
	}
	if strings.Contains(raw, testSecretValue) {
		t.Fatalf("history listing leaked the secret: %s", raw)
	}
	var items []struct {
		ID      int64  `json:"id"`
		URL     string `json:"url"`
		Status  int    `json:"status"`
		ReqText string `json:"req_redacted"`
		ResText string `json:"res_redacted"`
	}
	resp.decode(t, &items)
	if len(items) == 0 {
		t.Fatal("the executed request was not recorded in history")
	}
	if items[0].Status != http.StatusOK {
		t.Errorf("history status = %d, want 200", items[0].Status)
	}
	for _, it := range items {
		for field, value := range map[string]string{
			"url": it.URL, "req_redacted": it.ReqText, "res_redacted": it.ResText,
		} {
			if strings.Contains(value, testSecretValue) {
				t.Fatalf("history %s leaked the secret: %q", field, value)
			}
		}
	}

	// Nothing in the database itself may hold the plaintext.
	var leaks int
	if err := ts.db.QueryRow(`
		SELECT COUNT(*) FROM history
		WHERE url LIKE ? OR req_redacted LIKE ? OR res_redacted LIKE ?`,
		"%"+testSecretValue+"%", "%"+testSecretValue+"%", "%"+testSecretValue+"%").Scan(&leaks); err != nil {
		t.Fatalf("scan history for leaks: %v", err)
	}
	if leaks != 0 {
		t.Fatalf("%d history rows contain the plaintext secret", leaks)
	}

	// The single history detail view is redacted too.
	code, _, raw = ts.call("GET", "/api/history/"+idStr(items[0].ID), admin, nil)
	if code != http.StatusOK {
		t.Fatalf("history detail = %d (%s)", code, raw)
	}
	if strings.Contains(raw, testSecretValue) {
		t.Fatalf("history detail leaked the secret: %s", raw)
	}
}
