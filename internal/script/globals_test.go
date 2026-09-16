package script

import (
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"os"
	"strings"
	"testing"
)

// TestAtobBtoaMatchTheBrowser covers the two helpers Postman scripts reach for
// whenever a key or a signature crosses the string/bytes boundary.
func TestAtobBtoaMatchTheBrowser(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		out := runJS(t, `
			const raw = "\x00\x01\xffabc";
			globalThis.out = {
				b64: btoa(raw),
				back: atob(btoa(raw)),
				hello: btoa("hello"),
				decoded: atob("aGVsbG8="),
			};
		`)
		if out["b64"] != "AAH/YWJj" { // base64 of 00 01 ff 'a' 'b' 'c'
			t.Errorf("btoa = %v", out["b64"])
		}
		if out["back"] != "\x00\x01\u00ffabc" {
			t.Errorf("atob(btoa(x)) = %q", out["back"])
		}
		if out["hello"] != "aGVsbG8=" || out["decoded"] != "hello" {
			t.Errorf("btoa/atob = %v / %v", out["hello"], out["decoded"])
		}
	})

	t.Run("tolerates what a pasted key looks like", func(t *testing.T) {
		out := runJS(t, `
			globalThis.out = {
				wrapped: atob("aGVs\n bG8="),
				unpadded: atob("aGVsbG8"),
			};
		`)
		if out["wrapped"] != "hello" || out["unpadded"] != "hello" {
			t.Errorf("lenient atob = %v / %v", out["wrapped"], out["unpadded"])
		}
	})

	t.Run("rejects what cannot be represented", func(t *testing.T) {
		// btoa is not a UTF-8 encoder: a multi-byte character has no latin1 byte.
		msg := expectJSError(t, `btoa("牛")`, "btoa: invalid latin1 input")
		if !strings.Contains(msg, "InvalidCharacterError") {
			t.Errorf("error should be named InvalidCharacterError, got %q", msg)
		}
		// atob must fail closed rather than decode garbage.
		expectJSError(t, `atob("not base64!!")`, "atob: invalid base64 input")
	})
}

// TestAtobSaysWhatIsWrongWithItsInput covers the diagnostics, because
// "invalid base64 input" on its own is the message that sends someone to check a
// key that was never the problem — and the key must not be echoed back, since
// the error reaches the response body and the audit log.
func TestAtobSaysWhatIsWrongWithItsInput(t *testing.T) {
	t.Run("an unset variable is named as the cause", func(t *testing.T) {
		msg := expectJSError(t, `atob(pm.variables.get('PRIVATE_KEY_BASE64'))`, "expected a string, got undefined")
		if !strings.Contains(msg, "unset pm.variables") {
			t.Errorf("message = %q, want a hint about an unset variable", msg)
		}
	})

	t.Run("a placeholder is not expanded inside a script", func(t *testing.T) {
		// The mistake this exists for: {{sec.NAME}} in a pre-request script
		// arrives verbatim, because scripts run before variable resolution.
		msg := expectJSError(t, `atob('{{sec.PRIVATE_KEY_BASE64}}')`, "placeholder is not expanded")
		if !strings.Contains(msg, "pm.variables.get") {
			t.Errorf("message = %q, want the pm.variables.get hint", msg)
		}
	})

	t.Run("base64url is called what it is", func(t *testing.T) {
		expectJSError(t, `atob('nWGxne_9WmC6hEr0')`, "looks like base64url")
	})

	t.Run("the offending character is located, not quoted", func(t *testing.T) {
		// '****' is the masked value Task.md ships with: the report has to say
		// where it is wrong without printing it, since the same message is
		// audited.
		msg := expectJSError(t, `atob('****')`, "outside the base64 alphabet")
		if !strings.Contains(msg, "character 1") {
			t.Errorf("message = %q, want the character index", msg)
		}
		if !strings.Contains(msg, "mask") || !strings.Contains(msg, "pm.variables.get") {
			t.Errorf("message = %q, want the masked-key hint", msg)
		}
		if strings.Contains(msg, "****") {
			t.Errorf("message = %q, must not echo the value", msg)
		}
	})

	t.Run("an empty value says so", func(t *testing.T) {
		expectJSError(t, `atob('  ')`, "the input is empty")
	})

	t.Run("a valid key still decodes", func(t *testing.T) {
		out := runJS(t, `
			const seed = atob('nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=');
			globalThis.out = { len: seed.length, first: seed.charCodeAt(0) };
		`)
		if out["len"] != int64(32) || out["first"] != int64(0x9d) {
			t.Errorf("decoded seed = %v, want 32 bytes starting 0x9d", out)
		}
	})
}

func TestTextEncoderAndDecoder(t *testing.T) {
	t.Run("encode is UTF-8 into a Uint8Array", func(t *testing.T) {
		out := runJS(t, `
			const bytes = new TextEncoder().encode("POST\n牛");
			globalThis.out = {
				cls: Object.prototype.toString.call(bytes),
				len: bytes.length,
				lastThree: [bytes[bytes.length - 3], bytes[bytes.length - 2], bytes[bytes.length - 1]],
			};
		`)
		if out["cls"] != "[object Uint8Array]" {
			t.Errorf("encode() returned %v", out["cls"])
		}
		// "牛" is E7 89 9B in UTF-8.
		if out["len"] != int64(8) {
			t.Errorf("length = %v, want 8 (4 ascii + newline + 3 bytes)", out["len"])
		}
		got, _ := out["lastThree"].([]any)
		if len(got) != 3 || got[0] != int64(0xe7) || got[1] != int64(0x89) || got[2] != int64(0x9b) {
			t.Errorf("trailing bytes = %v, want [231 137 155]", got)
		}
	})

	t.Run("decode defaults to utf-8, takes latin1", func(t *testing.T) {
		out := runJS(t, `
			const bytes = new Uint8Array([0xe7, 0x89, 0x9b]);
			globalThis.out = {
				encoding: new TextDecoder().encoding,
				utf8: new TextDecoder().decode(bytes),
				latin1: new TextDecoder("latin1").decode(bytes),
				empty: new TextDecoder().decode(),
			};
		`)
		if out["encoding"] != "utf-8" || out["utf8"] != "牛" || out["empty"] != "" {
			t.Errorf("utf-8 decode = %v / %q / %q", out["encoding"], out["utf8"], out["empty"])
		}
		if out["latin1"] != "\u00e7\u0089\u009b" {
			t.Errorf("latin1 decode = %q, want the raw bytes as characters", out["latin1"])
		}
	})

	t.Run("bad input fails loudly", func(t *testing.T) {
		// A wrong label must not silently fall back to UTF-8 (mojibake is worse
		// than an error you can read).
		msg := expectJSError(t, `new TextDecoder("shift_jis")`, "unsupported encoding")
		if !strings.Contains(msg, "RangeError") {
			t.Errorf("error should be named RangeError, got %q", msg)
		}
		expectJSError(t, `new TextDecoder().decode(42)`, "expected a byte sequence")
	})

	t.Run("invalid utf-8 becomes the replacement character", func(t *testing.T) {
		// Non-fatal mode is the default, and reading a text body is the normal
		// reason to be here: a stray byte should not throw mid-script.
		out := runJS(t, `
			globalThis.out = { s: new TextDecoder().decode(new Uint8Array([0x61, 0xff, 0x62])) };
		`)
		if out["s"] != "a\uFFFDb" {
			t.Errorf("decode = %q", out["s"])
		}
	})
}

// TestTaskMdScriptRunsUnmodified is the migration guard: it runs the Postman
// pre-request script from Task.md verbatim (testdata/postman_sign_nacl.js, only
// the two values Task.md masks as '***' filled in) and checks the result with
// Go's crypto/ed25519. If a global or a pm.* method it uses ever disappears,
// this fails — which is the point, since "an old script keeps working" is the
// whole promise of the tweetnacl shim.
func TestTaskMdScriptRunsUnmodified(t *testing.T) {
	appKey := "demo-app-key"
	seedB64 := base64.StdEncoding.EncodeToString(hexBytes(rfcSeed1))

	raw, err := os.ReadFile("testdata/postman_sign_nacl.js")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	src := string(raw)
	for _, sub := range []struct{ masked, real string }{
		{"const APP_KEY = '***';", "const APP_KEY = '" + appKey + "';"},
		{"const PRIVATE_KEY_BASE64 = '***';", "const PRIVATE_KEY_BASE64 = '" + seedB64 + "';"},
	} {
		if !strings.Contains(src, sub.masked) {
			t.Fatalf("the fixture no longer contains %q", sub.masked)
		}
		src = strings.Replace(src, sub.masked, sub.real, 1)
	}

	const url = "http://api.example.test/openApi/v1/orders?page=2"
	env := NewEnv(&RequestCtx{Method: "POST", URL: url, BodyType: "none"}, map[string]string{})
	logs := &strings.Builder{}
	rt := New(WithConsole(logs))
	rt.Bind(env)

	if _, err := rt.Run("pre-request.js", src); err != nil {
		t.Fatalf("the Postman script does not run here: %v", err)
	}

	headers := env.HeaderMap()
	for _, want := range []string{
		"bsi-openapi-appkey", "bsi-openapi-sign", "bsi-openapi-timestamp",
		"bsi-openapi-nonce", "bsi-openapi-version",
	} {
		if headers[want] == "" {
			t.Errorf("header %q was not set (got %v)", want, headers)
		}
	}
	if headers["bsi-openapi-appkey"] != appKey || headers["bsi-openapi-version"] != "1.0.0" {
		t.Errorf("headers = %v", headers)
	}

	// The hand-rolled uuidv4() from the script still produces a v4 shape.
	nonce := headers["bsi-openapi-nonce"]
	if !uuidV4Re.MatchString(nonce) {
		t.Errorf("nonce = %q, want a uuid v4", nonce)
	}
	ts := headers["bsi-openapi-timestamp"]
	if len(ts) != 10 || strings.HasPrefix(ts, "0") {
		t.Errorf("timestamp = %q, want unix seconds", ts)
	}

	// Rebuild the signed text independently of the script: method, path+query
	// with /openApi stripped, timestamp, nonce — exactly the four lines the
	// service on the other end expects.
	signContent := "POST\n/v1/orders?page=2\n" + ts + "\n" + nonce
	sig, err := base64.StdEncoding.DecodeString(headers["bsi-openapi-sign"])
	if err != nil {
		t.Fatalf("signature is not base64: %v", err)
	}

	if !ed25519.Verify(ed25519.PublicKey(hexBytes(rfcPub1)), []byte(signContent), sig) {
		t.Fatalf("signature %q does not verify over %q", headers["bsi-openapi-sign"], signContent)
	}

	// The two console.log calls came through, which is what makes a script like
	// this debuggable from the response panel.
	if !strings.Contains(logs.String(), signContent) || !strings.Contains(logs.String(), headers["bsi-openapi-sign"]) {
		t.Errorf("console output = %q", logs.String())
	}
}

// TestMigratedTaskMdScriptReadsItsKeyFromVariables is the "what do I paste into
// the editor" guard: the same Task.md script with the two values it hardcodes
// (folded to '***' when the file is shared) read out of the variable bag
// instead. That is the only spelling that keeps a signing seed out of the script
// column, and the signature is checked with crypto/ed25519 so a passing test
// means the pasted script really signs what went out.
func TestMigratedTaskMdScriptReadsItsKeyFromVariables(t *testing.T) {
	const url = "http://api.example.test/openApi/v1/orders?page=2"
	const appKey = "demo-app-key"
	seedB64 := base64.StdEncoding.EncodeToString(hexBytes(rfcSeed1))

	run := func(t *testing.T, vars map[string]string) (*Env, error) {
		t.Helper()
		env := NewEnv(&RequestCtx{Method: "POST", URL: url, BodyType: "none"}, vars)
		rt := New(WithConsole(io.Discard))
		rt.Bind(env)
		_, err := rt.RunFile("testdata/task_md_migrated.js")
		return env, err
	}

	t.Run("the key comes from the variable bag", func(t *testing.T) {
		env, err := run(t, map[string]string{"APP_KEY": appKey, "PRIVATE_KEY_BASE64": seedB64})
		if err != nil {
			t.Fatalf("the migrated script does not run: %v", err)
		}
		headers := env.HeaderMap()
		for _, want := range []string{
			"bsi-openapi-appkey", "bsi-openapi-sign", "bsi-openapi-timestamp",
			"bsi-openapi-nonce", "bsi-openapi-version",
		} {
			if headers[want] == "" {
				t.Errorf("header %q was not set (got %v)", want, headers)
			}
		}
		if headers["bsi-openapi-appkey"] != appKey || headers["bsi-openapi-version"] != "1.0.0" {
			t.Errorf("headers = %v", headers)
		}

		// The four signed lines, rebuilt independently of the script.
		signContent := "POST\n/v1/orders?page=2\n" + headers["bsi-openapi-timestamp"] + "\n" + headers["bsi-openapi-nonce"]
		sig, err := base64.StdEncoding.DecodeString(headers["bsi-openapi-sign"])
		if err != nil {
			t.Fatalf("signature is not base64: %v", err)
		}
		if !ed25519.Verify(ed25519.PublicKey(hexBytes(rfcPub1)), []byte(signContent), sig) {
			t.Fatalf("signature %q does not verify over %q", headers["bsi-openapi-sign"], signContent)
		}
	})

	t.Run("an unset key names the variable instead of signing nothing", func(t *testing.T) {
		_, err := run(t, map[string]string{"APP_KEY": appKey})
		if err == nil {
			t.Fatal("the script signed with no key at all")
		}
		if !strings.Contains(ErrorMessage(err), "PRIVATE_KEY_BASE64") {
			t.Errorf("error = %q, want it to name the missing variable", ErrorMessage(err))
		}

		// Nothing set at all: the guard that trips first names its variable too,
		// instead of letting a header go out as the literal "undefined".
		_, err = run(t, nil)
		if err == nil || !strings.Contains(ErrorMessage(err), "APP_KEY") {
			t.Errorf("error = %v, want it to name APP_KEY", err)
		}
	})
}
