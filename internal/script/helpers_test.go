package script

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/dop251/goja"
)

// newTestRuntime builds a Runtime whose console output is thrown away.
func newTestRuntime(t *testing.T) *Runtime {
	t.Helper()
	return New(WithConsole(io.Discard))
}

// runJS runs src and returns the object the script assigned to globalThis.out.
func runJS(t *testing.T, src string) map[string]any {
	t.Helper()
	rt := newTestRuntime(t)
	if _, err := rt.Run("test.js", src); err != nil {
		t.Fatalf("run script: %v", err)
	}
	v := rt.Get("out")
	if v == nil {
		t.Fatal("script did not set globalThis.out")
	}
	m, ok := v.Export().(map[string]any)
	if !ok {
		t.Fatalf("out is %T, want an object", v.Export())
	}
	return m
}

// runScript runs src and returns the runtime (for tests recorded by pm.test)
// together with the object the script assigned to globalThis.out, if any.
func runScript(t *testing.T, src string) (*Runtime, map[string]any) {
	t.Helper()
	rt := newTestRuntime(t)
	if _, err := rt.Run("test.js", src); err != nil {
		t.Fatalf("run: %v", err)
	}
	var out map[string]any
	if v := rt.Get("out"); v != nil {
		out, _ = v.Export().(map[string]any)
	}
	return rt, out
}

// runJSValue runs src and returns its last expression value.
func runJSValue(t *testing.T, src string) goja.Value {
	t.Helper()
	v, err := newTestRuntime(t).Run("test.js", src)
	if err != nil {
		t.Fatalf("run script: %v", err)
	}
	return v
}

// expectJSError runs src, expects a JS exception, and returns its text
// ("TypeError: ...").
func expectJSError(t *testing.T, src, wantSubstring string) string {
	t.Helper()
	_, err := newTestRuntime(t).Run("test.js", src)
	if err == nil {
		t.Fatalf("expected an error from %q", src)
	}
	var ex *goja.Exception
	if !errors.As(err, &ex) {
		t.Fatalf("expected a JS exception, got %T: %v", err, err)
	}
	msg := ex.Value().String()
	if !strings.Contains(msg, wantSubstring) {
		t.Fatalf("error = %q, want it to contain %q", msg, wantSubstring)
	}
	return msg
}
