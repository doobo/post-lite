package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"postlite/internal/auth"
)

const loginPassword = "correct-horse-battery-staple"

// respOf parses the response envelope out of a raw recorder.
func respOf(t *testing.T, rec *httptest.ResponseRecorder) apiResp {
	t.Helper()
	var r apiResp
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("response is not JSON: %v (%s)", err, rec.Body.String())
	}
	return r
}

func sessionCookieFrom(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == "session" && c.Value != "" {
			return c
		}
	}
	t.Fatalf("no session cookie in response (Set-Cookie: %v)", rec.Header().Values("Set-Cookie"))
	return nil
}

func mustID(t *testing.T, code int, resp apiResp, raw string, wantStatus int) int64 {
	t.Helper()
	if code != wantStatus {
		t.Fatalf("status = %d, want %d (%s)", code, wantStatus, raw)
	}
	var d struct {
		ID int64 `json:"id"`
	}
	resp.decode(t, &d)
	if d.ID == 0 {
		t.Fatalf("response carried no id: %s", raw)
	}
	return d.ID
}

func mustFolder(t *testing.T, ts *testServer, cookie *http.Cookie, colID int64, parent *int64, name string) int64 {
	t.Helper()
	code, resp, raw := ts.call("POST", "/api/collections/"+idStr(colID)+"/folders", cookie,
		map[string]any{"name": name, "parent_id": parent})
	return mustID(t, code, resp, raw, http.StatusCreated)
}

func mustRequest(t *testing.T, ts *testServer, cookie *http.Cookie, body map[string]any) int64 {
	t.Helper()
	code, resp, raw := ts.call("POST", "/api/requests", cookie, body)
	return mustID(t, code, resp, raw, http.StatusCreated)
}

// ---- login / session ----

// encryptedLogin fetches a login key from the server and returns the request
// body the browser would post: the password, RSA-OAEP encrypted under the
// single-use challenge. Tests go through this instead of naming a plain-text
// field, which no longer exists.
func (ts *testServer) encryptedLogin(t *testing.T, ip, username, password string) map[string]any {
	t.Helper()

	rec := ts.callFrom("GET", "/api/auth/login-key", ip, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login-key = %d (%s)", rec.Code, rec.Body.String())
	}
	resp := respOf(t, rec)
	var key struct {
		N         string `json:"n"`
		E         int    `json:"e"`
		Challenge string `json:"challenge"`
	}
	resp.decode(t, &key)

	modulus, ok := new(big.Int).SetString(key.N, 16)
	if !ok {
		t.Fatalf("login key modulus %q is not hex", key.N)
	}
	// Rebuilding the key from n/e also proves the published numbers match the
	// private key: a mismatch would fail decryption on the server side.
	pub := &rsa.PublicKey{N: modulus, E: key.E}
	plain, err := json.Marshal(map[string]string{"c": key.Challenge, "p": password})
	if err != nil {
		t.Fatalf("marshal login payload: %v", err)
	}
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plain, nil)
	if err != nil {
		t.Fatalf("encrypt login payload: %v", err)
	}
	return map[string]any{"username": username, "enc": base64.StdEncoding.EncodeToString(ct)}
}

// TestLoginRefusesUnencryptedPasswords pins the contract that makes the
// handshake worth anything: there is no fallback to a clear-text password.
func TestLoginRefusesUnencryptedPasswords(t *testing.T) {
	ts := newTestServer(t)
	ts.createUser("alice", "user", loginPassword)

	rec := ts.callFrom("POST", "/api/auth/login", testRemoteAddr, nil,
		map[string]any{"username": "alice", "password": loginPassword})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("plain-text login = %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
	if r := respOf(t, rec); r.Error == nil || r.Error.Code != "encryption_required" {
		t.Errorf("error = %+v, want code encryption_required", r.Error)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Errorf("a refused login still set cookies: %v", rec.Result().Cookies())
	}
}

// TestLoginKeyIsSingleUse replays one captured ciphertext. Replay protection is
// the reason the challenge exists at all: without it, a logged request body is a
// working credential.
func TestLoginKeyIsSingleUse(t *testing.T) {
	ts := newTestServer(t)
	ts.createUser("alice", "user", loginPassword)
	body := ts.encryptedLogin(t, testRemoteAddr, "alice", loginPassword)

	first := ts.callFrom("POST", "/api/auth/login", testRemoteAddr, nil, body)
	if first.Code != http.StatusOK {
		t.Fatalf("first login = %d (%s)", first.Code, first.Body.String())
	}
	replay := ts.callFrom("POST", "/api/auth/login", testRemoteAddr, nil, body)
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replayed login = %d, want 400 (%s)", replay.Code, replay.Body.String())
	}
	if r := respOf(t, replay); r.Error == nil || r.Error.Code != "bad_login_payload" {
		t.Errorf("replay error = %+v, want code bad_login_payload", r.Error)
	}
	if len(replay.Result().Cookies()) != 0 {
		t.Errorf("a replayed login still set cookies: %v", replay.Result().Cookies())
	}
}

// TestLoginRejectsGarbageCiphertext covers tampered or truncated payloads.
func TestLoginRejectsGarbageCiphertext(t *testing.T) {
	ts := newTestServer(t)
	ts.createUser("alice", "user", loginPassword)

	for _, enc := range []string{"", "not-base64!!", base64.StdEncoding.EncodeToString(make([]byte, 256))} {
		rec := ts.callFrom("POST", "/api/auth/login", testRemoteAddr, nil,
			map[string]any{"username": "alice", "enc": enc})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("login with enc=%q = %d, want 400 (%s)", enc, rec.Code, rec.Body.String())
		}
	}
}

func TestLoginIssuesAWorkingSession(t *testing.T) {
	ts := newTestServer(t)
	uid := ts.createUser("alice", "user", loginPassword)

	rec := ts.callFrom("POST", "/api/auth/login", testRemoteAddr, nil,
		ts.encryptedLogin(t, testRemoteAddr, "alice", loginPassword))
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d (%s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), loginPassword) {
		t.Errorf("login response echoed the password: %s", rec.Body.String())
	}

	cookie := sessionCookieFrom(t, rec)
	if !cookie.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", cookie.SameSite)
	}
	if cookie.Path != "/" {
		t.Errorf("cookie path = %q, want /", cookie.Path)
	}
	if cookie.Secure != ts.cfg.SecureCookie {
		t.Errorf("cookie Secure = %v, want %v (follows the TLS config)", cookie.Secure, ts.cfg.SecureCookie)
	}
	if want := int(auth.SessionTTL.Seconds()); cookie.MaxAge != want {
		t.Errorf("cookie MaxAge = %d, want %d", cookie.MaxAge, want)
	}

	// Only the token hash may be persisted.
	var hashed, raw int
	if err := ts.db.QueryRow("SELECT COUNT(*) FROM sessions WHERE id = ?", auth.TokenHash(cookie.Value)).Scan(&hashed); err != nil {
		t.Fatalf("count hashed sessions: %v", err)
	}
	if err := ts.db.QueryRow("SELECT COUNT(*) FROM sessions WHERE id = ?", cookie.Value).Scan(&raw); err != nil {
		t.Fatalf("count raw sessions: %v", err)
	}
	if hashed != 1 {
		t.Errorf("sessions stored under the token hash = %d, want 1", hashed)
	}
	if raw != 0 {
		t.Error("the raw session token was stored in the sessions table")
	}

	// The cookie authenticates subsequent requests as that user.
	code, resp, rawBody := ts.call("GET", "/api/auth/me", cookie, nil)
	if code != http.StatusOK {
		t.Fatalf("me = %d (%s)", code, rawBody)
	}
	var me struct {
		User struct {
			ID       int64  `json:"id"`
			Username string `json:"username"`
			Role     string `json:"role"`
		} `json:"user"`
	}
	resp.decode(t, &me)
	if me.User.ID != uid || me.User.Username != "alice" || me.User.Role != "user" {
		t.Errorf("me = %+v, want alice (%d) as user", me.User, uid)
	}

	// Logout revokes the session server-side.
	if code, _, _ := ts.call("POST", "/api/auth/logout", cookie, nil); code != http.StatusOK {
		t.Fatalf("logout = %d, want 200", code)
	}
	if code, _, _ := ts.call("GET", "/api/auth/me", cookie, nil); code != http.StatusUnauthorized {
		t.Errorf("me after logout = %d, want 401", code)
	}
	if err := ts.db.QueryRow("SELECT COUNT(*) FROM sessions WHERE id = ?", auth.TokenHash(cookie.Value)).Scan(&hashed); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if hashed != 0 {
		t.Error("logout left the session row behind")
	}
}

func TestSessionCookieIsSecureUnderTLS(t *testing.T) {
	ts := newTestServer(t, withSecureCookie())
	ts.createUser("alice", "user", loginPassword)

	rec := ts.callFrom("POST", "/api/auth/login", testRemoteAddr, nil,
		ts.encryptedLogin(t, testRemoteAddr, "alice", loginPassword))
	if rec.Code != http.StatusOK {
		t.Fatalf("login = %d (%s)", rec.Code, rec.Body.String())
	}
	if c := sessionCookieFrom(t, rec); !c.Secure {
		t.Error("session cookie must be Secure when the server runs behind TLS")
	}
}

func TestLoginRateLimiting(t *testing.T) {
	ts := newTestServer(t)
	ts.createUser("alice", "user", loginPassword)

	const (
		ipA = "10.1.0.1:5000"
		ipB = "10.1.0.2:5000"
		ipC = "10.1.0.3:5000"
		ipD = "10.1.0.4:5000"
	)
	login := func(ip, user, pw string) *httptest.ResponseRecorder {
		return ts.callFrom("POST", "/api/auth/login", ip, nil,
			ts.encryptedLogin(t, ip, user, pw))
	}

	// A wrong password and an unknown account must be indistinguishable.
	badPw := login(ipA, "alice", "not-the-password")
	noUser := login(ipB, "nobody", "not-the-password")
	if badPw.Code != http.StatusUnauthorized || noUser.Code != http.StatusUnauthorized {
		t.Fatalf("failed logins = %d / %d, want 401 for both", badPw.Code, noUser.Code)
	}
	a, b := respOf(t, badPw), respOf(t, noUser)
	if a.Error == nil || b.Error == nil {
		t.Fatalf("failed logins carried no error: %+v / %+v", a.Error, b.Error)
	}
	if a.Error.Code != b.Error.Code || a.Error.Message != b.Error.Message {
		t.Errorf("failed logins reveal whether the account exists: %+v vs %+v", a.Error, b.Error)
	}

	// Five failures from one IP lock it, even for the correct password.
	for i := 0; i < 4; i++ {
		if rec := login(ipA, "alice", "not-the-password"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d = %d, want 401", i+2, rec.Code)
		}
	}
	locked := login(ipA, "alice", loginPassword)
	if locked.Code != http.StatusTooManyRequests {
		t.Fatalf("login while locked = %d, want 429", locked.Code)
	}
	if r := respOf(t, locked); r.Error == nil || r.Error.Code != "rate_limited" {
		t.Errorf("lockout error = %+v, want code rate_limited", r.Error)
	}

	// Unknown accounts are counted too.
	for i := 0; i < 4; i++ {
		if rec := login(ipB, "nobody", "x"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("unknown-user attempt %d = %d, want 401", i+2, rec.Code)
		}
	}
	if rec := login(ipB, "nobody", "x"); rec.Code != http.StatusTooManyRequests {
		t.Errorf("unknown-user attempts = %d, want 429 after five failures", rec.Code)
	}

	// A successful login clears the counter for that IP.
	for i := 0; i < 4; i++ {
		if rec := login(ipC, "alice", "not-the-password"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d = %d, want 401", i+1, rec.Code)
		}
	}
	if rec := login(ipC, "alice", loginPassword); rec.Code != http.StatusOK {
		t.Fatalf("login after four failures = %d, want 200", rec.Code)
	}
	for i := 0; i < 4; i++ {
		if rec := login(ipC, "alice", "not-the-password"); rec.Code != http.StatusUnauthorized {
			t.Errorf("failure %d after a successful login = %d, want 401 "+
				"(a success must reset the counter)", i+1, rec.Code)
		}
	}

	// One IP's lockout must not affect another.
	if rec := login(ipD, "alice", loginPassword); rec.Code != http.StatusOK {
		t.Errorf("login from an unrelated IP = %d, want 200", rec.Code)
	}
}

// ---- collection import / export ----

func TestCollectionImportExportRoundTrip(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))
	bob := ts.cookie(ts.createUser("bob", "user", loginPassword))

	colID := ts.createCollection(admin, "original", false)
	parent := mustFolder(t, ts, admin, colID, nil, "parent")
	child := mustFolder(t, ts, admin, colID, &parent, "child")
	mustRequest(t, ts, admin, map[string]any{
		"collection_id": colID,
		"folder_id":     child,
		"name":          "list-items",
		"method":        "POST",
		"url":           "http://10.0.0.1/v1/items",
		"headers":       `{"X-Tenant":"acme"}`,
		"query":         `[{"k":"page","v":"1"}]`,
		"body_type":     "json",
		"body":          `{"a":1}`,
	})

	// Export.
	rec := ts.callFrom("POST", "/api/collections/"+idStr(colID)+"/export", testRemoteAddr, admin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d (%s)", rec.Code, rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Errorf("Content-Disposition = %q, want an attachment download", cd)
	}
	exported := rec.Body.String()

	var exp struct {
		Name    string `json:"name"`
		Format  string `json:"format"`
		Folders []struct {
			ID       int64  `json:"id"`
			ParentID *int64 `json:"parent_id"`
			Name     string `json:"name"`
		} `json:"folders"`
		Requests []struct {
			ID       int64             `json:"id"`
			FolderID *int64            `json:"folder_id"`
			Name     string            `json:"name"`
			Method   string            `json:"method"`
			URL      string            `json:"url"`
			BodyType string            `json:"body_type"`
			Body     string            `json:"body"`
			Headers  map[string]string `json:"headers"`
			Query    []struct {
				K string `json:"k"`
				V string `json:"v"`
			} `json:"query"`
		} `json:"requests"`
	}
	if err := json.Unmarshal([]byte(exported), &exp); err != nil {
		t.Fatalf("export is not valid JSON: %v", err)
	}
	if exp.Name != "original" || exp.Format != "postlite/v1" {
		t.Errorf("export header = %q/%q, want original/postlite/v1", exp.Name, exp.Format)
	}
	if len(exp.Folders) != 2 || len(exp.Requests) != 1 {
		t.Fatalf("export holds %d folders and %d requests, want 2 and 1",
			len(exp.Folders), len(exp.Requests))
	}
	if exp.Requests[0].Headers["X-Tenant"] != "acme" {
		t.Errorf("exported headers = %v, want X-Tenant=acme", exp.Requests[0].Headers)
	}
	if len(exp.Requests[0].Query) != 1 || exp.Requests[0].Query[0].K != "page" || exp.Requests[0].Query[0].V != "1" {
		t.Errorf("exported query = %+v, want page=1", exp.Requests[0].Query)
	}

	// Someone else's collection cannot be exported.
	other := ts.callFrom("POST", "/api/collections/"+idStr(colID)+"/export", testRemoteAddr, bob, nil)
	if other.Code != http.StatusForbidden {
		t.Errorf("export by another user = %d, want 403", other.Code)
	}

	// Import the export back.
	code, resp, raw := ts.call("POST", "/api/collections/import", admin, map[string]any{"json": exported})
	newCol := mustID(t, code, resp, raw, http.StatusCreated)
	if newCol == colID {
		t.Fatal("import reused the original collection id")
	}

	code, resp, raw = ts.call("GET", "/api/collections/"+idStr(newCol), admin, nil)
	if code != http.StatusOK {
		t.Fatalf("get imported collection = %d (%s)", code, raw)
	}
	var got struct {
		Collection struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		} `json:"collection"`
		Folders []struct {
			ID       int64  `json:"id"`
			ParentID *int64 `json:"parent_id"`
			Name     string `json:"name"`
		} `json:"folders"`
		Requests []struct {
			FolderID *int64 `json:"folder_id"`
			Name     string `json:"name"`
			Method   string `json:"method"`
			URL      string `json:"url"`
			BodyType string `json:"body_type"`
			Body     string `json:"body"`
			Headers  string `json:"headers"`
			Query    string `json:"query"`
		} `json:"requests"`
	}
	resp.decode(t, &got)
	if got.Collection.ID != newCol || got.Collection.Name != "original" {
		t.Errorf("imported collection = %+v, want id %d named original", got.Collection, newCol)
	}
	if len(got.Folders) != 2 || len(got.Requests) != 1 {
		t.Fatalf("imported %d folders and %d requests, want 2 and 1",
			len(got.Folders), len(got.Requests))
	}

	// Folder ids are remapped and the nesting survives.
	ids := map[string]int64{}
	for _, f := range got.Folders {
		ids[f.Name] = f.ID
		if f.ID == parent || f.ID == child {
			t.Errorf("folder %q kept its exported id %d", f.Name, f.ID)
		}
	}
	if ids["parent"] == 0 || ids["child"] == 0 {
		t.Fatalf("imported folders = %+v, want parent and child", got.Folders)
	}
	for _, f := range got.Folders {
		switch f.Name {
		case "parent":
			if f.ParentID != nil {
				t.Errorf("imported parent has ParentID %v, want nil", f.ParentID)
			}
		case "child":
			if f.ParentID == nil || *f.ParentID != ids["parent"] {
				t.Errorf("imported child ParentID = %v, want %d", f.ParentID, ids["parent"])
			}
		}
	}

	rq := got.Requests[0]
	if rq.Name != "list-items" || rq.Method != "POST" || rq.URL != "http://10.0.0.1/v1/items" {
		t.Errorf("imported request = %+v, want the exported name, method and url", rq)
	}
	if rq.BodyType != "json" || rq.Body != `{"a":1}` {
		t.Errorf("imported body = %q (%s), want json {\"a\":1}", rq.Body, rq.BodyType)
	}
	if rq.Headers != `{"X-Tenant":"acme"}` {
		t.Errorf("imported headers = %q, want the exported object", rq.Headers)
	}
	if rq.Query != `[{"k":"page","v":"1"}]` {
		t.Errorf("imported query = %q, want the exported pairs", rq.Query)
	}
	if rq.FolderID == nil || *rq.FolderID != ids["child"] {
		t.Errorf("imported request FolderID = %v, want the new child folder %d", rq.FolderID, ids["child"])
	}
}

func TestCollectionImportValidation(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))
	bob := ts.cookie(ts.createUser("bob", "user", loginPassword))

	exported := "{\"name\":\"imported\",\"format\":\"postlite/v1\"}"

	rejected := []struct {
		name string
		body map[string]any
	}{
		{"malformed JSON", map[string]any{"json": "this is not json"}},
		{"missing name", map[string]any{"json": `{"format":"postlite/v1"}`}},
		{"empty document", map[string]any{"json": ""}},
	}
	for _, tc := range rejected {
		code, resp, raw := ts.call("POST", "/api/collections/import", admin, tc.body)
		if code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (%s)", tc.name, code, raw)
			continue
		}
		if resp.Error == nil || resp.Error.Code != "bad_request" {
			t.Errorf("%s: error = %+v, want code bad_request", tc.name, resp.Error)
		}
	}

	// Only admins may import into the global scope.
	code, _, raw := ts.call("POST", "/api/collections/import", bob,
		map[string]any{"json": exported, "global": true})
	if code != http.StatusForbidden {
		t.Errorf("non-admin global import = %d, want 403 (%s)", code, raw)
	}

	// A private import is owned by the importing user.
	code, resp, raw := ts.call("POST", "/api/collections/import", bob, map[string]any{"json": exported})
	privateCol := mustID(t, code, resp, raw, http.StatusCreated)
	if code, _, _ := ts.call("GET", "/api/collections/"+idStr(privateCol), admin, nil); code != http.StatusOK {
		t.Errorf("admin reading a user's import = %d, want 200", code)
	}
	if code, _, _ := ts.call("GET", "/api/collections/"+idStr(privateCol), bob, nil); code != http.StatusOK {
		t.Errorf("owner reading their import = %d, want 200", code)
	}

	// A global import is visible to every user.
	code, resp, raw = ts.call("POST", "/api/collections/import", admin,
		map[string]any{"json": exported, "global": true})
	globalCol := mustID(t, code, resp, raw, http.StatusCreated)
	if code, _, _ := ts.call("GET", "/api/collections/"+idStr(globalCol), bob, nil); code != http.StatusOK {
		t.Errorf("user reading a global import = %d, want 200", code)
	}
	if code, _, _ := ts.call("GET", "/api/collections", bob, nil); code != http.StatusOK {
		t.Errorf("listing collections after a global import = %d, want 200", code)
	}
	if err := ts.db.QueryRow("SELECT COUNT(*) FROM collections WHERE id = ? AND owner_id IS NULL", globalCol).
		Scan(new(int)); err != nil {
		t.Errorf("global import is not ownerless: %v", err)
	}

	// The request body cap (4MB) applies to imports.
	oversized := map[string]any{"json": strings.Repeat("a", 4<<20)}
	if code, _, raw := ts.call("POST", "/api/collections/import", admin, oversized); code != http.StatusBadRequest {
		t.Errorf("oversized import = %d, want 400 (%s)", code, truncateForLog(raw))
	}
}

func truncateForLog(s string) string {
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

// ---- settings ----

func TestSettingsRequireAdmin(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))
	user := ts.cookie(ts.createUser("user1", "user", loginPassword))

	for _, cookie := range []*http.Cookie{nil, user} {
		want := http.StatusUnauthorized
		if cookie != nil {
			want = http.StatusForbidden
		}
		if code, _, _ := ts.call("GET", "/api/settings", cookie, nil); code != want {
			t.Errorf("GET /api/settings = %d, want %d", code, want)
		}
		if code, _, _ := ts.call("PUT", "/api/settings", cookie, map[string]string{"max_history": "5"}); code != want {
			t.Errorf("PUT /api/settings = %d, want %d", code, want)
		}
	}

	// Nothing a non-admin tried was persisted.
	code, resp, raw := ts.call("GET", "/api/settings", admin, nil)
	if code != http.StatusOK {
		t.Fatalf("admin GET /api/settings = %d (%s)", code, raw)
	}
	var got map[string]string
	resp.decode(t, &got)
	if got["max_history"] != "1000" {
		t.Errorf("max_history = %q after rejected writes, want the default 1000", got["max_history"])
	}
}

func TestSettingsDefaultsAndValidation(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))

	// Defaults.
	code, resp, raw := ts.call("GET", "/api/settings", admin, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /api/settings = %d (%s)", code, raw)
	}
	var defaults map[string]string
	resp.decode(t, &defaults)
	if !strings.Contains(defaults["ssrf_whitelist"], "10.0.0.0/8") ||
		!strings.Contains(defaults["ssrf_whitelist"], "127.0.0.0/8") {
		t.Errorf("default ssrf_whitelist = %q, want the private CIDRs", defaults["ssrf_whitelist"])
	}
	if defaults["exec_timeout"] != ts.cfg.Timeout.String() {
		t.Errorf("default exec_timeout = %q, want %q", defaults["exec_timeout"], ts.cfg.Timeout.String())
	}
	if defaults["max_history"] != "1000" {
		t.Errorf("default max_history = %q, want 1000", defaults["max_history"])
	}

	// On a fresh install GET returns flag-derived values and the UI saves them
	// straight back, so the defaults must always be accepted verbatim.
	if code, _, raw := ts.call("PUT", "/api/settings", admin, defaults); code != http.StatusOK {
		t.Errorf("saving GET's defaults back = %d, want 200 (%s)", code, raw)
	}

	// Valid values round-trip through the UI form (GET values are PUTtable).
	valid := map[string]string{
		"ssrf_whitelist": "10.0.0.0/8,127.0.0.0/8",
		"exec_timeout":   "90s",
		"max_history":    "25",
	}
	code, resp, raw = ts.call("PUT", "/api/settings", admin, valid)
	if code != http.StatusOK {
		t.Fatalf("PUT /api/settings = %d (%s)", code, raw)
	}
	var saved struct {
		Saved []string `json:"saved"`
	}
	resp.decode(t, &saved)
	if len(saved.Saved) != len(valid) {
		t.Errorf("saved = %v, want all %d keys", saved.Saved, len(valid))
	}
	code, resp, raw = ts.call("GET", "/api/settings", admin, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /api/settings = %d (%s)", code, raw)
	}
	var after map[string]string
	resp.decode(t, &after)
	for k, want := range valid {
		if after[k] != want {
			t.Errorf("settings[%s] = %q, want %q", k, after[k], want)
		}
	}

	// The UI saves whatever GET returned, so that must always be accepted.
	if code, _, raw := ts.call("PUT", "/api/settings", admin, after); code != http.StatusOK {
		t.Errorf("re-saving GET's own values = %d, want 200 (%s)", code, raw)
	}

	// Invalid values are rejected outright.
	rejected := []struct {
		name string
		body map[string]string
	}{
		{"unknown key", map[string]string{"shell": "/bin/sh"}},
		{"bad CIDR", map[string]string{"ssrf_whitelist": "not-a-cidr"}},
		{"CIDR prefix out of range", map[string]string{"ssrf_whitelist": "10.0.0.0/33"}},
		{"timeout not a duration", map[string]string{"exec_timeout": "soon"}},
		{"timeout zero", map[string]string{"exec_timeout": "0"}},
		{"timeout negative", map[string]string{"exec_timeout": "-5s"}},
		{"history not a number", map[string]string{"max_history": "lots"}},
		{"history zero", map[string]string{"max_history": "0"}},
		{"history negative", map[string]string{"max_history": "-1"}},
	}
	for _, tc := range rejected {
		code, resp, raw := ts.call("PUT", "/api/settings", admin, tc.body)
		if code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (%s)", tc.name, code, raw)
			continue
		}
		if resp.Error == nil || resp.Error.Code != "bad_request" {
			t.Errorf("%s: error = %+v, want code bad_request", tc.name, resp.Error)
		}
	}

	// A rejected update must not be half-applied: pair a good key with a bad
	// one and check the good key kept its previous value.
	mixed := map[string]string{"max_history": "12", "exec_timeout": "whenever"}
	if code, _, _ := ts.call("PUT", "/api/settings", admin, mixed); code != http.StatusBadRequest {
		t.Errorf("mixed valid/invalid update = %d, want 400", code)
	}
	code, resp, _ = ts.call("GET", "/api/settings", admin, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /api/settings = %d", code)
	}
	var final map[string]string
	resp.decode(t, &final)
	if final["max_history"] != after["max_history"] {
		t.Errorf("max_history = %q after a rejected update, want it unchanged at %q",
			final["max_history"], after["max_history"])
	}
	if final["exec_timeout"] != after["exec_timeout"] {
		t.Errorf("exec_timeout = %q after a rejected update, want it unchanged at %q",
			final["exec_timeout"], after["exec_timeout"])
	}

	// A non-JSON body is refused.
	if code, _, _ := ts.call("PUT", "/api/settings", admin, "just a string"); code != http.StatusBadRequest {
		t.Errorf("PUT with a non-object body = %d, want 400", code)
	}
}

func TestSettingsTakeEffect(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))

	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer echo.Close()

	execute := func(target string) (int, apiResp, string) {
		return ts.call("POST", "/api/execute", admin,
			map[string]any{"ad_hoc": map[string]any{"method": "GET", "url": target}})
	}

	// The whitelist setting is consulted per execution: excluding the local
	// server blocks it, including it allows it.
	if code, _, raw := ts.call("PUT", "/api/settings", admin,
		map[string]string{"ssrf_whitelist": "10.0.0.0/8"}); code != http.StatusOK {
		t.Fatalf("restrict whitelist = %d (%s)", code, raw)
	}
	code, resp, raw := execute(echo.URL)
	if code != http.StatusUnavailableForLegalReasons {
		t.Errorf("execute outside the configured whitelist = %d, want 451 (%s)", code, raw)
	}
	if resp.Error == nil || resp.Error.Code != "ssrf_blocked" {
		t.Errorf("error = %+v, want code ssrf_blocked", resp.Error)
	}

	if code, _, raw := ts.call("PUT", "/api/settings", admin,
		map[string]string{"ssrf_whitelist": "127.0.0.0/8"}); code != http.StatusOK {
		t.Fatalf("allow local whitelist = %d (%s)", code, raw)
	}
	if code, _, raw := execute(echo.URL); code != http.StatusOK {
		t.Errorf("execute inside the configured whitelist = %d, want 200 (%s)", code, raw)
	}

	// max_history bounds the retained rows.
	if code, _, raw := ts.call("PUT", "/api/settings", admin,
		map[string]string{"max_history": "2"}); code != http.StatusOK {
		t.Fatalf("set max_history = %d (%s)", code, raw)
	}
	for i := 0; i < 3; i++ {
		if code, _, raw := execute(echo.URL); code != http.StatusOK {
			t.Fatalf("execute %d = %d (%s)", i+1, code, raw)
		}
	}
	code, resp, raw = ts.call("GET", "/api/history", admin, nil)
	if code != http.StatusOK {
		t.Fatalf("list history = %d (%s)", code, raw)
	}
	var items []struct {
		ID int64 `json:"id"`
	}
	resp.decode(t, &items)
	if len(items) != 2 {
		t.Errorf("history holds %d rows with max_history=2, want 2", len(items))
	}

	// exec_timeout accepts a duration string and is honoured.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1500 * time.Millisecond)
		_, _ = io.WriteString(w, "late")
	}))
	defer slow.Close()

	if code, _, raw := ts.call("PUT", "/api/settings", admin,
		map[string]string{"exec_timeout": "1s"}); code != http.StatusOK {
		t.Fatalf("set exec_timeout = %d (%s)", code, raw)
	}
	code, resp, raw = execute(slow.URL)
	if code != http.StatusGatewayTimeout {
		t.Errorf("execute past the configured timeout = %d, want 504 (%s)", code, raw)
	}
	if resp.Error == nil || resp.Error.Code != "timeout" {
		t.Errorf("error = %+v, want code timeout", resp.Error)
	}

	// Defence in depth: a garbage value written straight to the database (as an
	// older release could have) is still rejected when it is used.
	if err := ts.store.Settings.Set("ssrf_whitelist", "not-a-cidr"); err != nil {
		t.Fatalf("write settings row: %v", err)
	}
	code, resp, raw = execute(echo.URL)
	if code != http.StatusBadRequest {
		t.Errorf("execute with a corrupt whitelist = %d, want 400 (%s)", code, raw)
	}
	if resp.Error == nil || !strings.Contains(resp.Error.Message, "ssrf_whitelist") {
		t.Errorf("error = %+v, want it to name the bad setting", resp.Error)
	}
}
