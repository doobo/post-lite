package script

import (
	"strings"
	"testing"
)

func testResponse() *ResponseCtx {
	return &ResponseCtx{
		Code:       201,
		Status:     "201 Created",
		DurationMS: 42,
		Body:       `{"user":{"name":"ada","roles":["admin"]},"token":"***"}`,
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
			"X-Trace":      {"trace-1"},
			"Set-Cookie":   {"a=1", "b=2"},
		},
		FinalURL: "http://api.internal:8080/users",
	}
}

func runWithResponse(t *testing.T, src string) (*Runtime, map[string]any) {
	t.Helper()
	rt := newTestRuntime(t)
	env := NewEnv(&RequestCtx{Method: "POST", URL: "http://api.internal:8080/users", Headers: [][2]string{{"X-Sent", "yes"}}}, map[string]string{"who": "ada"})
	env.Response = testResponse()
	rt.Bind(env)
	if _, err := rt.Run("test.js", src); err != nil {
		t.Fatalf("run: %v", err)
	}
	var out map[string]any
	if v := rt.Get("out"); v != nil {
		out, _ = v.Export().(map[string]any)
	}
	return rt, out
}

func TestResponseFields(t *testing.T) {
	_, out := runWithResponse(t, `
		globalThis.out = {
			code: pm.response.code,
			status: pm.response.status,
			time: pm.response.responseTime,
			size: pm.response.responseSize,
			text: pm.response.text(),
			name: pm.response.json().user.name,
			rolesLength: pm.response.json().user.roles.length,
			header: pm.response.headers.get('x-trace'),
			headerMissing: pm.response.headers.get('nope') === null,
			has: pm.response.headers.has('Content-Type'),
			all: pm.response.headers.all().length,
			joined: pm.response.headers.toObject()['Set-Cookie'],
			requestHeader: pm.request.headers.get('X-Sent'),
		};
	`)
	for field, want := range map[string]any{
		"code":          int64(201),
		"status":        "201 Created",
		"time":          int64(42),
		"size":          int64(len(testResponse().Body)),
		"text":          testResponse().Body,
		"name":          "ada",
		"rolesLength":   int64(1),
		"header":        "trace-1",
		"headerMissing": true,
		"has":           true,
		"all":           int64(4),
		"joined":        "a=1, b=2",
		"requestHeader": "yes",
	} {
		if got := out[field]; got != want {
			t.Errorf("%s = %v (%T), want %v (%T)", field, got, got, want, want)
		}
	}
}

func TestResponseHeadersEach(t *testing.T) {
	_, out := runWithResponse(t, `
		const seen = [];
		pm.response.headers.each((h) => seen.push(h.key + '=' + h.value));
		globalThis.out = {seen: seen.join('|')};
	`)
	if out["seen"] != "Content-Type=application/json|Set-Cookie=a=1, b=2|X-Trace=trace-1" {
		t.Errorf("each() = %v", out["seen"])
	}
}

func TestResponseAssertions(t *testing.T) {
	cases := []struct {
		name string
		expr string
		pass bool
		msg  string
	}{
		{name: "status", expr: "pm.response.to.have.status(201)", pass: true},
		{name: "status-fails", expr: "pm.response.to.have.status(200)", msg: "expected response to have status code 200 but got 201"},
		{name: "header", expr: "pm.response.to.have.header('X-Trace')", pass: true},
		{name: "header-case-insensitive", expr: "pm.response.to.have.header('x-trace', 'trace-1')", pass: true},
		{name: "header-value-fails", expr: "pm.response.to.have.header('X-Trace', 'trace-2')", msg: `expected header "X-Trace" to equal "trace-2" but got "trace-1"`},
		{name: "header-missing", expr: "pm.response.to.have.header('X-Nope')", msg: `expected response to have header "X-Nope"`},
		{name: "ok", expr: "pm.response.to.be.ok", pass: true},
		{name: "json", expr: "pm.response.to.be.json", pass: true},
		{name: "error-fails", expr: "pm.response.to.be.error", msg: "expected response to be an error (4xx/5xx) but got 201"},
		{name: "text-fails", expr: "pm.response.to.be.text", msg: "to be text"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, _ := runWithResponse(t, "pm.test('case', () => { "+tc.expr+"; });")
			results := rt.Tests()
			if len(results) != 1 {
				t.Fatalf("recorded %d results", len(results))
			}
			if results[0].Passed != tc.pass {
				t.Fatalf("passed = %v, want %v (message %q)", results[0].Passed, tc.pass, results[0].Message)
			}
			if tc.msg != "" && !strings.Contains(results[0].Message, tc.msg) {
				t.Errorf("message = %q, want it to contain %q", results[0].Message, tc.msg)
			}
		})
	}
}

func TestResponseAssertionErrorsAreCatchableByPmTest(t *testing.T) {
	// A failed pm.response.to assertion is an AssertionError, so it is recorded
	// as a failed test rather than aborting the script.
	rt, out := runWithResponse(t, `
		pm.test('fails', () => { pm.response.to.have.status(500); });
		pm.test('still runs', () => { pm.expect(pm.response.code).to.equal(201); });
		globalThis.out = {ran: true};
	`)
	results := rt.Tests()
	if len(results) != 2 || results[0].Passed || !results[1].Passed {
		t.Fatalf("results = %+v", results)
	}
	if out["ran"] != true {
		t.Error("the script stopped after a failed response assertion")
	}
}

func TestResponseJSONError(t *testing.T) {
	rt := newTestRuntime(t)
	env := NewEnv(&RequestCtx{}, nil)
	env.Response = &ResponseCtx{Code: 200, Body: "not json"}
	rt.Bind(env)
	_, err := rt.Run("test.js", "pm.response.json()")
	if err == nil {
		t.Fatal("expected an error for a non-JSON body")
	}
	if !strings.Contains(err.Error(), "not valid JSON") {
		t.Errorf("error = %v", err)
	}
}

func TestResponseIsUndefinedWithoutBinding(t *testing.T) {
	// A pre-request script has no pm.response (and pm.test/pm.expect need no
	// request context at all).
	_, out := runScript(t, `
		globalThis.out = {
			response: typeof pm.response,
			test: typeof pm.test,
			expect: typeof pm.expect,
			tests: typeof tests,
		};
	`)
	for field, want := range map[string]any{"response": "undefined", "test": "function", "expect": "function", "tests": "object"} {
		if got := out[field]; got != want {
			t.Errorf("%s = %v, want %v", field, got, want)
		}
	}
}
