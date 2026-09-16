package script

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestRuntimeRequireCachesPerRuntime(t *testing.T) {
	rt := newTestRuntime(t)
	a, err := rt.Require("npm:tweetnacl@1.0.3")
	if err != nil {
		t.Fatal(err)
	}
	b, err := rt.Require("tweetnacl")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Error("aliases should resolve to the same cached module object")
	}

	// A fresh Runtime gets its own copy (module state is not shared).
	c, err := newTestRuntime(t).Require("npm:tweetnacl@1.0.3")
	if err != nil {
		t.Fatal(err)
	}
	if c == a {
		t.Error("two runtimes share a module object")
	}
}

func TestRuntimeRequireUnknownModule(t *testing.T) {
	msg := expectJSError(t, "pm.require('npm:lodash@4.17.21')", "cannot find module 'npm:lodash@4.17.21'")
	if !strings.Contains(msg, "npm:tweetnacl@1.0.3") {
		t.Errorf("error should list the builtins, got %q", msg)
	}
}

func TestRuntimeExposesOnlyItsOwnGlobals(t *testing.T) {
	out := runJS(t, `
		globalThis.out = {
			pm: typeof pm,
			pmRequire: typeof pm.require,
			pmCrypto: typeof pm.crypto.ed25519.sign,
			console: typeof console.log,
			bareRequire: typeof require,
			process: typeof process,
		};
	`)
	for field, want := range map[string]any{
		"pm": "object", "pmRequire": "function", "pmCrypto": "function", "console": "function",
		"bareRequire": "undefined", "process": "undefined",
	} {
		if got := out[field]; got != want {
			t.Errorf("%s = %v, want %v", field, got, want)
		}
	}
}

func TestRuntimeSetGet(t *testing.T) {
	rt := newTestRuntime(t)
	if err := rt.Set("hostPID", "req-7"); err != nil {
		t.Fatal(err)
	}
	if got := runJSValueOn(t, rt, "hostPID + '!'"); got != "req-7!" {
		t.Errorf("global = %v", got)
	}
	if rt.Get("missing") != nil {
		t.Error("undefined global should come back as nil")
	}
}

func runJSValueOn(t *testing.T, rt *Runtime, src string) string {
	t.Helper()
	v, err := rt.Run("test.js", src)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return v.String()
}

func TestRuntimeTimeout(t *testing.T) {
	rt := New(WithConsole(io.Discard), WithTimeout(50*time.Millisecond))
	start := time.Now()
	_, err := rt.Run("spin.js", "while (true) {}")
	if err == nil {
		t.Fatal("expected the runaway script to be interrupted")
	}
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("error = %v, want ErrTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("interrupt took %s, the deadline did not fire", elapsed)
	}

	// The Runtime stays usable afterwards.
	if got := runJSValueOn(t, rt, "1 + 1"); got != "2" {
		t.Errorf("runtime not reusable after a timeout: %v", got)
	}
}

func TestRuntimeInterruptFromAnotherGoroutine(t *testing.T) {
	rt := New(WithConsole(io.Discard))
	go func() {
		time.Sleep(20 * time.Millisecond)
		rt.Interrupt("cancelled")
	}()
	if _, err := rt.Run("spin.js", "while (true) {}"); err == nil {
		t.Fatal("expected an interrupt")
	}
	if got := runJSValueOn(t, rt, "'alive'"); got != "alive" {
		t.Errorf("runtime not reusable after an interrupt: %v", got)
	}
}

func TestRuntimeSyntaxAndRuntimeErrors(t *testing.T) {
	rt := newTestRuntime(t)
	if _, err := rt.Run("pre-request.js", "const = 1;"); err == nil {
		t.Fatal("expected a syntax error")
	} else if !strings.Contains(err.Error(), "pre-request.js") {
		t.Errorf("syntax error should name the script, got %v", err)
	}

	_, err := rt.Run("pre-request.js", "notDefined()")
	if err == nil {
		t.Fatal("expected a ReferenceError")
	}
	if !strings.Contains(err.Error(), "notDefined") {
		t.Errorf("error = %v", err)
	}
}

func TestRuntimeRunFileMissing(t *testing.T) {
	if _, err := newTestRuntime(t).RunFile("testdata/nope.js"); err == nil {
		t.Fatal("expected an error for a missing script")
	}
}

func TestRuntimeConsole(t *testing.T) {
	var buf bytes.Buffer
	rt := New(WithConsole(&buf))
	if _, err := rt.Run("c.js", `
		console.log('signed %s at %d', 'POST', 1700000000);
		console.warn('json', {a: 1, b: [2, 3]});
		console.error('plain', 'two');
	`); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	for _, want := range []string{
		"signed POST at 1700000000",
		`json {"a":1,"b":[2,3]}`,
		"plain two",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("console output %q missing %q", got, want)
		}
	}
}

func TestConsoleNeverFailsAScript(t *testing.T) {
	// A circular object cannot be JSON-rendered; console.log must still not throw.
	rt := New(WithConsole(io.Discard))
	if _, err := rt.Run("c.js", "const a = {b: 1}; a.self = a; console.log(a, function f() {});"); err != nil {
		t.Fatalf("console.log failed: %v", err)
	}
}

func TestRuntimeOptions(t *testing.T) {
	custom := NewRegistry(TweetNaclModule{})
	rt := New(WithRegistry(custom), WithRegistry(nil))
	if _, err := rt.Require("npm:uuid@9.0.0"); err == nil {
		t.Error("a custom registry should not fall back to the default modules")
	}
	if _, err := rt.Require("npm:tweetnacl@1.0.3"); err != nil {
		t.Errorf("tweetnacl should resolve: %v", err)
	}
}

// TestExampleScriptProducesAVerifiableSignature runs the example from
// docs/post-lite-script.md end to end and checks its output with Go's
// crypto/ed25519: the fix is not the implementation agreeing with itself, it is
// the signature verifying against the RFC 8032 public key.
func TestExampleScriptProducesAVerifiableSignature(t *testing.T) {
	rt := New(WithConsole(&bytes.Buffer{}))
	if _, err := rt.RunFile("testdata/postman_sign.js"); err != nil {
		t.Fatalf("run example: %v", err)
	}
	res, ok := rt.Get("result").Export().(map[string]any)
	if !ok {
		t.Fatalf("the script did not set globalThis.result")
	}

	signContent, _ := res["signContent"].(string)
	if !strings.HasPrefix(signContent, "POST\n/openApi/v1/orders\n") {
		t.Errorf("signContent = %q", signContent)
	}
	if nonce, _ := res["nonce"].(string); nonce == "" || !uuidV4Re.MatchString(nonce) {
		t.Errorf("nonce = %v, want a uuid v4", res["nonce"])
	}

	pub := ed25519.PublicKey(hexBytes(rfcPub1))
	sigB64, _ := res["signature"].(string)
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("signature is not base64: %v", err)
	}
	if !ed25519.Verify(pub, []byte(signContent), sig) {
		t.Fatalf("signature %s does not verify against the RFC 8032 public key", sigB64)
	}

	// Both tracks of the doc produced the very same signature.
	if res["legacySignature"] != res["signature"] {
		t.Errorf("compat layer = %v, native API = %v", res["legacySignature"], res["signature"])
	}
	if got := res["publicKey"]; got != rfcPub1 {
		t.Errorf("publicKey = %v, want %s", got, rfcPub1)
	}
	headers, _ := res["headers"].(map[string]any)
	if headers["bsi-openapi-sign"] != sigB64 || headers["bsi-openapi-appkey"] != "demo-app-key" {
		t.Errorf("headers = %v", headers)
	}
}
