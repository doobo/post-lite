package script

import (
	"strings"
	"testing"
)

func runWithEnv(t *testing.T, script string, req *RequestCtx, vars map[string]string) (*Env, error) {
	t.Helper()
	rt := newTestRuntime(t)
	env := NewEnv(req, vars)
	rt.Bind(env)
	_, err := rt.Run("pre-request.js", script)
	return env, err
}

func TestRequestContextReadWrite(t *testing.T) {
	req := &RequestCtx{
		Method:   "GET",
		URL:      "http://api.internal:8080/openApi/orders?tenant=7",
		BodyType: "raw",
		Body:     "original",
		Headers:  [][2]string{{"Content-Type", "text/plain"}},
	}
	env, err := runWithEnv(t, `
		pm.request.headers.upsert({key: 'X-Signature', value: 'abc'});
		pm.request.headers.upsert({key: 'content-type', value: 'application/json'});
		pm.request.headers.add({key: 'X-Trace', value: '1'});
		pm.request.headers.add({key: 'X-Trace', value: '2'});
		pm.request.headers.remove('X-Missing');
		pm.request.body.raw = 'rewritten';
		pm.request.method = 'POST';
		pm.request.url = pm.request.url.toString() + '&extra=1';
	`, req, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if req.Method != "POST" {
		t.Errorf("method = %s", req.Method)
	}
	if req.URL != "http://api.internal:8080/openApi/orders?tenant=7&extra=1" {
		t.Errorf("url = %s", req.URL)
	}
	if req.Body != "rewritten" {
		t.Errorf("body = %s", req.Body)
	}
	want := map[string]string{"X-Signature": "abc", "content-type": "application/json", "X-Trace": "2"}
	got := env.HeaderMap()
	if len(got) != len(want) {
		t.Fatalf("headers = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("header %s = %q, want %q", k, got[k], v)
		}
	}
	// upsert replaced the existing spelling instead of adding a second one.
	count := 0
	for _, h := range req.Headers {
		if h[0] == "content-type" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("content-type appears %d times, want 1", count)
	}
}

func TestRequestURLAccessors(t *testing.T) {
	cases := []struct {
		url, pathWithQuery, path, query, host string
	}{
		{"http://h:5680/openApi/orders?tenant=7", "/openApi/orders?tenant=7", "/openApi/orders", "tenant=7", "h:5680"},
		{"https://h/openApi", "/openApi", "/openApi", "", "h"},
		{"http://h", "/", "/", "", "h"},
		{"http://h/{{tenant}}/x", "/{{tenant}}/x", "/{{tenant}}/x", "", "h"},
		{"/relative/path?a=1", "/relative/path?a=1", "/relative/path", "a=1", ""},
		{"", "/", "/", "", ""},
	}
	for _, tc := range cases {
		out := runJSWithReq(t, `
			globalThis.out = {
				pq: pm.request.url.getPathWithQuery(),
				p: pm.request.url.getPath(),
				q: pm.request.url.getQueryString(),
				h: pm.request.url.getHost(),
				text: String(pm.request.url),
			};
		`, &RequestCtx{Method: "GET", URL: tc.url}, nil)

		for field, want := range map[string]any{"pq": tc.pathWithQuery, "p": tc.path, "q": tc.query, "h": tc.host, "text": tc.url} {
			if got := out[field]; got != want {
				t.Errorf("%s for %q = %v, want %v", field, tc.url, got, want)
			}
		}
	}
}

func TestRequestBodyMode(t *testing.T) {
	out := runJSWithReq(t, `
		const before = pm.request.body.mode;
		pm.request.body.update({raw: 'from-update'});
		globalThis.out = {before, after: pm.request.body.raw, text: pm.request.body.toString()};
	`, &RequestCtx{Method: "POST", URL: "http://h/x", BodyType: "json", Body: "{}"}, nil)
	for field, want := range map[string]any{"before": "json", "after": "from-update", "text": "from-update"} {
		if got := out[field]; got != want {
			t.Errorf("%s = %v, want %v", field, got, want)
		}
	}
}

func TestRequestHeaderHelpers(t *testing.T) {
	out := runJSWithReq(t, `
		pm.request.headers.add({key: 'A', value: '1'});
		pm.request.headers.add({key: 'B', value: '2'});
		const seen = [];
		pm.request.headers.each((h, i) => seen.push(i + ':' + h.key + '=' + h.value));
		globalThis.out = {
			has: pm.request.headers.has('a'),
			get: pm.request.headers.get('B'),
			missing: pm.request.headers.get('nope') === null,
			all: pm.request.headers.all().length,
			seen: seen.join(','),
			obj: JSON.stringify(pm.request.headers.toObject()),
			text: pm.request.headers.toString(),
		};
	`, &RequestCtx{Method: "GET", URL: "http://h/"}, nil)

	for field, want := range map[string]any{
		"has":     true,
		"get":     "2",
		"missing": true,
		"all":     int64(2),
		"seen":    "0:A=1,1:B=2",
		"obj":     `{"A":"1","B":"2"}`,
		"text":    "A: 1\nB: 2",
	} {
		if got := out[field]; got != want {
			t.Errorf("%s = %v, want %v", field, got, want)
		}
	}
}

func TestRequestHeadersOnEmptyRequest(t *testing.T) {
	out := runJSWithReq(t, `
		globalThis.out = {
			all: pm.request.headers.all().length,
			text: pm.request.headers.toString(),
			method: pm.request.method,
			body: pm.request.body.raw,
		};
	`, &RequestCtx{}, nil)
	for field, want := range map[string]any{"all": int64(0), "text": "", "method": "", "body": ""} {
		if got := out[field]; got != want {
			t.Errorf("%s = %v, want %v", field, got, want)
		}
	}
}

func TestVariablesScope(t *testing.T) {
	env, err := runWithEnv(t, `
		// pm.environment / pm.globals are views of the same merged bag.
		pm.environment.set('tenant', 'acme');
		pm.variables.set('nonce', 42);
		const seen = {
			tenant: pm.globals.get('tenant'),
			nonce: pm.variables.get('nonce'),
			has: pm.variables.has('tenant'),
			missing: pm.variables.get('nope'),
			all: JSON.stringify(pm.variables.toObject()),
		};
		pm.variables.unset('nonce');
		globalThis.out = Object.assign(seen, {
			afterUnset: pm.variables.has('nonce'),
			replaced: pm.variables.replaceIn('t={{tenant}} s={{sec.api_key}} u={{unknown}}'),
		});
	`, &RequestCtx{}, map[string]string{"seed": "keep"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	// nonce was set and then unset, so it is neither in the bag nor in the
	// reported changes: the net effect of the script is nothing.
	if len(env.Changed) != 1 || env.Changed["tenant"] != "acme" {
		t.Errorf("changed = %v, want only tenant", env.Changed)
	}
	if _, still := env.Vars["nonce"]; still {
		t.Error("unset left the variable behind")
	}
	if env.Vars["seed"] != "keep" {
		t.Errorf("the pre-existing variable was lost: %v", env.Vars)
	}
}

func TestVariablesReplaceIn(t *testing.T) {
	out := runJSWithReq(t, `
		globalThis.out = {
			known: pm.variables.replaceIn('{{a}}/{{b}}'),
			missing: pm.variables.replaceIn('x={{nope}}'),
			// Secrets are never in the bag, so they survive for the server-side
			// resolver instead of silently becoming empty.
			secret: pm.variables.replaceIn('{{sec.api_key}}'),
			undefinedValue: pm.variables.get('nope'),
		};
	`, &RequestCtx{}, map[string]string{"a": "1", "b": "2"})

	if raw := out["known"]; raw != "1/2" {
		t.Errorf("known = %v, want 1/2", raw)
	}
	if out["missing"] != "x={{nope}}" {
		t.Errorf("missing = %v, want the placeholder left alone", out["missing"])
	}
	if out["secret"] != "{{sec.api_key}}" {
		t.Errorf("secret = %v, want the placeholder left for the server", out["secret"])
	}
	if out["undefinedValue"] != nil {
		t.Errorf("pm.variables.get on a missing name = %v, want undefined", out["undefinedValue"])
	}
}

func TestSortedHeadersIsDeterministic(t *testing.T) {
	got := SortedHeaders(map[string]string{"b": "2", "a": "1", "c": "3"})
	want := [][2]string{{"a", "1"}, {"b", "2"}, {"c", "3"}}
	if len(got) != len(want) {
		t.Fatalf("SortedHeaders = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SortedHeaders = %v, want %v", got, want)
		}
	}
}

func TestBindRequestErrors(t *testing.T) {
	rt := newTestRuntime(t)
	rt.Bind(nil) // must not panic

	rt2 := newTestRuntime(t)
	rt2.Bind(NewEnv(&RequestCtx{}, nil))
	if _, err := rt2.Run("x.js", "pm.request.method + pm.request.headers.toString()"); err != nil {
		t.Fatalf("zero-value request context failed: %v", err)
	}

	for _, tc := range []struct{ src, want string }{
		{"pm.request.headers.add('nope')", "expected {key, value}"},
		{"pm.request.headers.add({value: 'v'})", "key is required"},
		{"pm.request.headers.each('nope')", "a function is required"},
	} {
		rt3 := newTestRuntime(t)
		rt3.Bind(NewEnv(&RequestCtx{}, nil))
		_, err := rt3.Run("pre-request.js", tc.src)
		if err == nil {
			t.Errorf("%s did not fail", tc.src)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s error = %v, want %q", tc.src, err, tc.want)
		}
	}
}

// runJSWithReq runs a script with a bound request context and returns the
// globalThis.out object.
func runJSWithReq(t *testing.T, src string, req *RequestCtx, vars map[string]string) map[string]any {
	t.Helper()
	rt := newTestRuntime(t)
	rt.Bind(NewEnv(req, vars))
	if _, err := rt.Run("pre-request.js", src); err != nil {
		t.Fatalf("run: %v", err)
	}
	v := rt.Get("out")
	if v == nil {
		t.Fatal("script did not set globalThis.out")
	}
	m, ok := v.Export().(map[string]any)
	if !ok {
		t.Fatalf("out is %T", v.Export())
	}
	return m
}
