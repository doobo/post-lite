package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"postlite/internal/config"
)

// RFC 8032 test-1 seed: the signature a pre-request script produces here is
// checked against it with crypto/ed25519, so a passing test means the sandbox
// really signed what the request went out with.
const scriptTestSeedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
const scriptTestSecret = "super-secret-value"

// scriptUpstream records everything the executed request put on the wire.
type scriptUpstream struct {
	srv     *httptest.Server
	mu      sync.Mutex
	calls   int
	method  string
	path    string
	query   string
	headers http.Header
	body    string
}

func newScriptUpstream(t *testing.T) *scriptUpstream {
	t.Helper()
	up := &scriptUpstream{}
	up.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		up.mu.Lock()
		up.calls++
		up.method = r.Method
		up.path = r.URL.Path
		up.query = r.URL.RawQuery
		up.headers = r.Header.Clone()
		up.body = string(b)
		up.mu.Unlock()
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(up.srv.Close)
	return up
}

func (u *scriptUpstream) snapshot() (int, string, string, string, http.Header, string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.calls, u.method, u.path, u.query, u.headers, u.body
}

func scriptTestSeedB64() string {
	raw, err := hex.DecodeString(scriptTestSeedHex)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// scriptResponse is the part of an execute response the script tests look at.
type scriptResponse struct {
	Status int `json:"status"`
	Script struct {
		Logs  []string          `json:"logs"`
		Vars  map[string]string `json:"vars"`
		Tests []struct {
			Name    string `json:"name"`
			Passed  bool   `json:"passed"`
			Message string `json:"message"`
		} `json:"tests"`
		TestError string `json:"test_error"`
	} `json:"script"`
}

func TestPreRequestScriptSignsAndRewritesRequest(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))
	up := newScriptUpstream(t)

	if code, _, raw := ts.call("POST", "/api/secrets", admin,
		map[string]any{"name": "api_key", "value": scriptTestSecret}); code != http.StatusCreated {
		t.Fatalf("create secret = %d (%s)", code, raw)
	}

	// The script reads the request, signs it with a seed from the variable bag,
	// rewrites the method/body, injects a secret placeholder and a variable.
	script := `
const seed = pm.variables.get('seed');
const url = pm.request.url.getPathWithQuery();
const body = pm.request.body.raw;
const content = pm.request.method + '\n' + url + '\n' + body;
const signature = pm.crypto.ed25519.sign({
  seed: seed, seedEncoding: 'base64', data: content,
  inputEncoding: 'utf8', outputEncoding: 'base64',
});
pm.request.headers.upsert({key: 'X-Signature', value: signature});
pm.request.headers.upsert({key: 'X-Secret', value: '{{sec.api_key}}'});
pm.request.headers.upsert({key: 'X-Secret-Visible', value: String(pm.variables.get('sec.api_key'))});
pm.request.headers.add({key: 'X-Nonce', value: pm.require('npm:uuid@9.0.0').v4()});
pm.request.body.raw = 'rewritten body';
pm.request.method = 'POST';
pm.variables.set('signed', 'yes');
console.log('signed %s %s', pm.request.method, url);
`

	code, resp, raw := ts.call("POST", "/api/execute", admin, map[string]any{
		"ad_hoc": map[string]any{
			"method":    "GET",
			"url":       up.srv.URL + "/openApi/orders?tenant=7",
			"body_type": "raw",
			"body":      "original body",
			"script":    script,
		},
		"vars": map[string]string{"seed": scriptTestSeedB64()},
	})
	if code != http.StatusOK {
		t.Fatalf("execute with a script = %d (%s)", code, raw)
	}

	calls, method, path, query, headers, body := up.snapshot()
	if calls != 1 {
		t.Fatalf("upstream received %d calls, want 1", calls)
	}
	if method != "POST" {
		t.Errorf("method = %s, want POST (the script rewrote it)", method)
	}
	if path != "/openApi/orders" || !strings.Contains(query, "tenant=7") {
		t.Errorf("upstream got %s?%s, want /openApi/orders?tenant=7", path, query)
	}
	if body != "rewritten body" {
		t.Errorf("body = %q, want the script's rewrite", body)
	}
	if got := headers.Get("X-Secret-Visible"); got != "undefined" {
		t.Errorf("a script could read a secret: X-Secret-Visible = %q", got)
	}
	if got := headers.Get("X-Secret"); got != scriptTestSecret {
		t.Errorf("X-Secret = %q, want the server to expand {{sec.api_key}} after the script", got)
	}
	if got := headers.Get("X-Nonce"); len(got) != 36 {
		t.Errorf("X-Nonce = %q, want a uuid from the builtin module", got)
	}

	// The signature must cover what the script actually saw.
	signContent := "GET\n/openApi/orders?tenant=7\noriginal body"
	sig, err := base64.StdEncoding.DecodeString(headers.Get("X-Signature"))
	if err != nil {
		t.Fatalf("X-Signature is not base64: %v", err)
	}
	seed, _ := hex.DecodeString(scriptTestSeedHex)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, []byte(signContent), sig) {
		t.Errorf("X-Signature does not verify over %q", signContent)
	}

	var out scriptResponse
	resp.decode(t, &out)
	if len(out.Script.Logs) != 1 || !strings.Contains(out.Script.Logs[0], "signed POST /openApi/orders?tenant=7") {
		t.Errorf("script logs = %v", out.Script.Logs)
	}
	if out.Script.Vars["signed"] != "yes" {
		t.Errorf("script vars = %v, want signed=yes", out.Script.Vars)
	}
	// The secret never comes back to the caller, not even through the script.
	if strings.Contains(raw, scriptTestSecret) {
		t.Errorf("execute response leaked the secret: %s", raw)
	}
}

// TestPreRequestScriptOnStoredRequest covers the request_id path: the script
// lives on the row, not in the ad-hoc body.
func TestPreRequestScriptOnStoredRequest(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))
	up := newScriptUpstream(t)
	coll := ts.createCollection(admin, "signed", false)

	script := `pm.request.headers.upsert({key: 'X-From-Row', value: pm.variables.get('who')});`
	code, resp, raw := ts.call("POST", "/api/requests", admin, map[string]any{
		"collection_id": coll,
		"name":          "signed call",
		"method":        "GET",
		"url":           up.srv.URL + "/row",
		"script":        script,
	})
	if code != http.StatusCreated {
		t.Fatalf("create request with a script = %d (%s)", code, raw)
	}
	var created struct {
		ID int64 `json:"id"`
	}
	resp.decode(t, &created)

	// The script round-trips through the API.
	code, resp, raw = ts.call("GET", "/api/requests/"+idStr(created.ID), admin, nil)
	if code != http.StatusOK {
		t.Fatalf("get request = %d (%s)", code, raw)
	}
	var stored struct {
		Script string `json:"script"`
	}
	resp.decode(t, &stored)
	if stored.Script != script {
		t.Errorf("stored script = %q, want %q", stored.Script, script)
	}

	code, _, raw = ts.call("POST", "/api/execute", admin, map[string]any{
		"request_id": created.ID,
		"vars":       map[string]string{"who": "row-script"},
	})
	if code != http.StatusOK {
		t.Fatalf("execute stored request = %d (%s)", code, raw)
	}
	if _, _, _, _, headers, _ := up.snapshot(); headers.Get("X-From-Row") != "row-script" {
		t.Errorf("the stored script did not run: headers = %v", headers)
	}
}

// TestTestScriptRecordsResults covers the post-response phase: assertions on
// what came back are recorded as test results, and a failing assertion is
// information — the request already happened, so the HTTP status stays 200.
func TestTestScriptRecordsResults(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))
	up := newRecordingUpstream(t, `{"user":{"name":"ada"},"count":2}`)

	code, resp, raw := ts.call("POST", "/api/execute", admin, map[string]any{
		"ad_hoc": map[string]any{
			"method": "GET",
			"url":    up.srv.URL + "/users",
			"script": "pm.variables.set('signed', 'yes');",
			"test_script": `
pm.test('status is 200', () => { pm.response.to.have.status(200); });
pm.test('body has a user', () => {
  const body = pm.response.json();
  pm.expect(body.user.name).to.equal('ada');
  pm.expect(body.count).to.be.above(1);
});
pm.test('this one fails', () => { pm.expect(pm.response.code).to.equal(500); });
pm.test('the pre-request variable survived', () => {
  pm.expect(pm.variables.get('signed')).to.equal('yes');
});
tests['legacy style'] = pm.response.headers.get('Content-Type') !== null;
`,
		},
	})
	if code != http.StatusOK {
		t.Fatalf("execute with a test script = %d (%s), want 200", code, raw)
	}

	var out scriptResponse
	resp.decode(t, &out)
	tests := out.Script.Tests
	if len(tests) != 5 {
		t.Fatalf("recorded %d tests, want 5: %+v", len(tests), tests)
	}
	for i, want := range []struct {
		name   string
		passed bool
	}{
		{"status is 200", true},
		{"body has a user", true},
		{"this one fails", false},
		{"the pre-request variable survived", true},
		{"legacy style", true},
	} {
		if tests[i].Name != want.name || tests[i].Passed != want.passed {
			t.Errorf("test %d = %+v, want %q passed=%v", i, tests[i], want.name, want.passed)
		}
	}
	if !strings.Contains(tests[2].Message, "expected 200 to equal 500") {
		t.Errorf("failure message = %q", tests[2].Message)
	}
	if out.Script.TestError != "" {
		t.Errorf("test_error = %q, want none", out.Script.TestError)
	}
}

// TestTestScriptSeesMaskedSecrets is the leak guard for the post-response
// phase: a secret echoed back by the upstream must reach the script already
// masked, or an assertion message could ferry it to the browser.
func TestTestScriptSeesMaskedSecrets(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))
	if code, _, raw := ts.call("POST", "/api/secrets", admin,
		map[string]any{"name": "api_key", "value": scriptTestSecret}); code != http.StatusCreated {
		t.Fatalf("create secret = %d (%s)", code, raw)
	}

	// The upstream echoes the secret back in the body and in a header.
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo", r.Header.Get("X-Secret"))
		_, _ = io.WriteString(w, `{"token":"`+r.Header.Get("X-Secret")+`"}`)
	}))
	defer up.Close()

	code, resp, raw := ts.call("POST", "/api/execute", admin, map[string]any{
		"ad_hoc": map[string]any{
			"method":  "GET",
			"url":     up.URL,
			"headers": map[string]string{"X-Secret": "{{sec.api_key}}"},
			"test_script": `
pm.variables.set('seenBody', pm.response.text());
pm.variables.set('seenHeader', pm.response.headers.get('X-Echo'));
pm.test('the secret is masked', () => {
  pm.expect(pm.response.text()).to.include('***');
  pm.expect(pm.response.headers.get('X-Echo')).to.equal('***');
});
`,
		},
	})
	if code != http.StatusOK {
		t.Fatalf("execute = %d (%s)", code, raw)
	}

	var out scriptResponse
	resp.decode(t, &out)
	if len(out.Script.Tests) != 1 || !out.Script.Tests[0].Passed {
		t.Fatalf("tests = %+v", out.Script.Tests)
	}
	if strings.Contains(raw, scriptTestSecret) {
		t.Fatalf("the response leaked the secret: %s", raw)
	}
	if !strings.Contains(out.Script.Vars["seenBody"], "***") {
		t.Errorf("the script saw an unmasked body: %q", out.Script.Vars["seenBody"])
	}
	if out.Script.Vars["seenHeader"] != "***" {
		t.Errorf("the script saw an unmasked header: %q", out.Script.Vars["seenHeader"])
	}
}

// TestMigratedPostmanTestScriptRunsUnchanged is the migration case the sandbox
// exists for: a test script copied out of a Postman collection, unmodified.
func TestMigratedPostmanTestScriptRunsUnchanged(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))
	up := newRecordingUpstream(t, `{"user":{"name":"ada"},"roles":["admin","user"]}`)

	code, resp, raw := ts.call("POST", "/api/execute", admin, map[string]any{
		"ad_hoc": map[string]any{
			"method": "GET",
			"url":    up.srv.URL + "/graphql",
			"test_script": `
pm.test("Status code is 200", function () {
    pm.response.to.have.status(200);
});

pm.test("Response time is less than 500ms", function () {
    pm.expect(pm.response.responseTime).to.be.below(500);
});

pm.test("Content-Type is present", function () {
    pm.response.to.have.header("Content-Type");
});

pm.test("Body matches string", function () {
    pm.expect(pm.response.text()).to.include("ada");
});

pm.test("User has the admin role", function () {
    const jsonData = pm.response.json();
    pm.expect(jsonData.user.name).to.eql("ada");
    pm.expect(jsonData.roles).to.be.an("array").that.includes("admin");
});

pm.test("A deliberately failing assertion", function () {
    pm.expect(pm.response.code).to.equal(201);
});
`,
		},
	})
	if code != http.StatusOK {
		t.Fatalf("execute = %d (%s)", code, raw)
	}
	var out scriptResponse
	resp.decode(t, &out)
	results := out.Script.Tests
	if len(results) != 6 {
		t.Fatalf("recorded %d tests, want 6: %+v", len(results), results)
	}
	for i, want := range []string{"Status code is 200", "Response time is less than 500ms", "Content-Type is present", "Body matches string", "User has the admin role"} {
		if results[i].Name != want {
			t.Errorf("test %d = %q, want %q", i, results[i].Name, want)
		}
		if !results[i].Passed {
			t.Errorf("test %q failed: %s", want, results[i].Message)
		}
	}
	if results[5].Passed || !strings.Contains(results[5].Message, "expected 200 to equal 201") {
		t.Errorf("last test = %+v, want a recorded failure", results[5])
	}
}

func TestTestScriptCrashIsReportedNotFatal(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))
	up := newRecordingUpstream(t, "ok")

	code, resp, raw := ts.call("POST", "/api/execute", admin, map[string]any{
		"ad_hoc": map[string]any{"method": "GET", "url": up.srv.URL, "test_script": "pm.response.nope();"},
	})
	if code != http.StatusOK {
		t.Fatalf("a crashing test script = %d (%s), want the response anyway", code, raw)
	}
	var out scriptResponse
	resp.decode(t, &out)
	if out.Script.TestError == "" {
		t.Fatal("test_error is empty, want the crash reported")
	}
	if !strings.Contains(out.Script.TestError, "nope") {
		t.Errorf("test_error = %q", out.Script.TestError)
	}
	if !ts.auditedAction("execute.test_script_error") {
		t.Error("a test-script crash was not audited")
	}
}

func TestPreRequestScriptErrorBlocksTheRequest(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))
	up := newScriptUpstream(t)

	code, resp, raw := ts.call("POST", "/api/execute", admin, map[string]any{
		"ad_hoc": map[string]any{
			"method": "GET",
			"url":    up.srv.URL,
			"script": `pm.request.headers.upsert({key: 'X-Late', value: 'never'}); throw new Error('signing key missing');`,
		},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("execute with a failing script = %d (%s), want 400", code, raw)
	}
	if resp.Error == nil || resp.Error.Code != "script_error" {
		t.Fatalf("error = %+v, want code script_error", resp.Error)
	}
	if !strings.Contains(resp.Error.Message, "signing key missing") {
		t.Errorf("error message = %q, want the script's own message", resp.Error.Message)
	}
	if calls, _, _, _, _, _ := up.snapshot(); calls != 0 {
		t.Errorf("upstream received %d calls after a script error, want 0", calls)
	}
	if !ts.auditedAction("execute.script_error") {
		t.Error("a script error was not audited")
	}
}

func TestPreRequestScriptTimeout(t *testing.T) {
	ts := newTestServer(t, func(c *config.Config) { c.ScriptTimeout = 150 * time.Millisecond })
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))
	up := newScriptUpstream(t)

	start := time.Now()
	code, resp, raw := ts.call("POST", "/api/execute", admin, map[string]any{
		"ad_hoc": map[string]any{"method": "GET", "url": up.srv.URL, "script": "while (true) {}"},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("runaway script = %d (%s), want 400", code, raw)
	}
	if resp.Error == nil || resp.Error.Code != "script_timeout" {
		t.Fatalf("error = %+v, want code script_timeout", resp.Error)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("the script timeout was not applied (took %s)", elapsed)
	}
	if calls, _, _, _, _, _ := up.snapshot(); calls != 0 {
		t.Errorf("upstream received %d calls after a timeout, want 0", calls)
	}
}

func TestPreRequestScriptVariableOrder(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))
	up := newScriptUpstream(t)

	// A script-set variable wins over the editor's temporary vars and over the
	// environment, because the script runs last but before resolution.
	code, _, raw := ts.call("POST", "/api/execute", admin, map[string]any{
		"ad_hoc": map[string]any{
			"method": "GET",
			"url":    up.srv.URL + "/{{tenant}}",
			"script": "pm.variables.set('tenant', 'from-script');",
		},
		"vars": map[string]string{"tenant": "from-editor"},
	})
	if code != http.StatusOK {
		t.Fatalf("execute = %d (%s)", code, raw)
	}
	if _, _, path, _, _, _ := up.snapshot(); path != "/from-script" {
		t.Errorf("upstream path = %q, want the script's variable to win", path)
	}
}

func TestPreRequestScriptValidation(t *testing.T) {
	ts := newTestServer(t)
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))
	coll := ts.createCollection(admin, "scripts", false)

	// Realtime rows have no pre-request pipeline, so a script is refused rather
	// than stored and silently ignored.
	code, resp, raw := ts.call("POST", "/api/requests", admin, map[string]any{
		"collection_id": coll, "name": "ws", "protocol": "ws", "method": "GET",
		"url": "ws://example.test/socket", "script": "console.log('never runs')",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("script on a ws request = %d (%s), want 400", code, raw)
	}
	if resp.Error == nil || !strings.Contains(resp.Error.Message, "only supported for http") {
		t.Errorf("error = %+v", resp.Error)
	}

	// Oversized scripts are refused at the door.
	code, resp, _ = ts.call("POST", "/api/requests", admin, map[string]any{
		"collection_id": coll, "name": "big", "method": "GET",
		"url": "http://example.test/", "script": strings.Repeat("x", (64<<10)+1),
	})
	if code != http.StatusBadRequest {
		t.Fatalf("oversized script = %d, want 400", code)
	}
	if resp.Error == nil || !strings.Contains(resp.Error.Message, "too long") {
		t.Errorf("error = %+v", resp.Error)
	}

	// The same guard covers the post-response script.
	code, resp, _ = ts.call("POST", "/api/requests", admin, map[string]any{
		"collection_id": coll, "name": "big-tests", "method": "GET",
		"url": "http://example.test/", "test_script": strings.Repeat("x", (64<<10)+1),
	})
	if code != http.StatusBadRequest {
		t.Fatalf("oversized test script = %d, want 400", code)
	}
	if resp.Error == nil || !strings.Contains(resp.Error.Message, "test_script is too long") {
		t.Errorf("error = %+v", resp.Error)
	}

	// ...but normal ones are accepted and survive export/import.
	const script = "pm.variables.set('a', 'b');"
	const testScript = "pm.test('ok', () => { pm.response.to.be.ok; });"
	code, resp, raw = ts.call("POST", "/api/requests", admin, map[string]any{
		"collection_id": coll, "name": "signed", "method": "GET",
		"url": "http://example.test/", "script": script, "test_script": testScript,
	})
	if code != http.StatusCreated {
		t.Fatalf("create with a script = %d (%s)", code, raw)
	}
	var created struct {
		ID int64 `json:"id"`
	}
	resp.decode(t, &created)

	rec := ts.callFrom("POST", "/api/collections/"+idStr(coll)+"/export", testRemoteAddr, admin, nil)
	exported := rec.Body.String()
	if !strings.Contains(exported, `"script": "pm.variables.set('a', 'b');"`) {
		t.Errorf("exported collection does not carry the pre-request script: %s", exported)
	}
	if !strings.Contains(exported, `"test_script":`) {
		t.Errorf("exported collection does not carry the test script: %s", exported)
	}

	code, resp, raw = ts.call("POST", "/api/collections/import", admin, map[string]any{"json": exported})
	if code != http.StatusCreated {
		t.Fatalf("import = %d (%s)", code, raw)
	}
	var imported struct {
		ID int64 `json:"id"`
	}
	resp.decode(t, &imported)

	code, resp, raw = ts.call("GET", "/api/requests?collection_id="+idStr(imported.ID), admin, nil)
	if code != http.StatusOK {
		t.Fatalf("list imported requests = %d (%s)", code, raw)
	}
	var listed []struct {
		Script     string `json:"script"`
		TestScript string `json:"test_script"`
	}
	resp.decode(t, &listed)
	if len(listed) != 1 || listed[0].Script != script || listed[0].TestScript != testScript {
		t.Errorf("imported scripts = %+v, want the originals", listed)
	}
}
