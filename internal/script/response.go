package script

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/dop251/goja"
)

// ResponseCtx is the read-only view a post-response script gets of what came
// back. Everything in it is already redacted (secrets masked as "***"), the same
// text the browser is shown: a script must not be able to lift a secret out of a
// response into a test message, which is what would happen if it saw the raw
// body.
type ResponseCtx struct {
	Code       int
	Status     string
	DurationMS int64
	Body       string
	Headers    map[string][]string
	Truncated  bool
	FinalURL   string
}

// responseObject builds pm.response:
//
//	pm.response.code / status / responseTime / responseSize
//	pm.response.text() / json()
//	pm.response.headers.get(name) / has / all / toObject / each
//	pm.response.to.have.status(200) / .have.header('X-Trace') / .be.ok / .be.error / .be.json
//
// The `.to` assertions throw the same AssertionError pm.expect does, so they can
// be used inside pm.test and be recorded instead of aborting the script.
func responseObject(vm *goja.Runtime, resp *ResponseCtx) *goja.Object {
	obj := vm.NewObject()
	obj.Set("code", resp.Code)
	obj.Set("status", resp.Status)
	obj.Set("responseTime", resp.DurationMS)
	obj.Set("responseSize", len(resp.Body))
	obj.Set("text", func(goja.FunctionCall) goja.Value { return vm.ToValue(resp.Body) })
	obj.Set("json", func(goja.FunctionCall) goja.Value { return responseJSON(vm, resp) })
	obj.Set("headers", responseHeadersObject(vm, resp.Headers))
	obj.Set("to", responseAssertions(vm, resp))
	return obj
}

func responseJSON(vm *goja.Runtime, resp *ResponseCtx) goja.Value {
	var parsed any
	if err := json.Unmarshal([]byte(resp.Body), &parsed); err != nil {
		throwType(vm, "pm.response.json: the response body is not valid JSON (%v)", err)
	}
	return vm.ToValue(parsed)
}

// responseHeadersObject is the read-only counterpart of pm.request.headers:
// lookup is case-insensitive, like HTTP itself.
func responseHeadersObject(vm *goja.Runtime, headers map[string][]string) *goja.Object {
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)

	value := func(name string) ([]string, string, bool) {
		for _, k := range names {
			if strings.EqualFold(k, name) {
				// HTTP repeats a header for multiple values; the editor shows
				// them joined, and so does this.
				return headers[k], strings.Join(headers[k], ", "), true
			}
		}
		return nil, "", false
	}

	obj := vm.NewObject()
	obj.Set("get", func(call goja.FunctionCall) goja.Value {
		if _, joined, found := value(call.Argument(0).String()); found {
			return vm.ToValue(joined)
		}
		return goja.Null()
	})
	obj.Set("has", func(call goja.FunctionCall) goja.Value {
		_, _, found := value(call.Argument(0).String())
		return vm.ToValue(found)
	})
	obj.Set("all", func(goja.FunctionCall) goja.Value {
		out := make([]any, 0, len(names))
		for _, k := range names {
			for _, v := range headers[k] {
				pair := vm.NewObject()
				pair.Set("key", k)
				pair.Set("value", v)
				out = append(out, pair)
			}
		}
		return vm.ToValue(out)
	})
	obj.Set("toObject", func(goja.FunctionCall) goja.Value {
		o := vm.NewObject()
		for _, k := range names {
			o.Set(k, strings.Join(headers[k], ", "))
		}
		return o
	})
	obj.Set("each", func(call goja.FunctionCall) goja.Value {
		fn, ok := goja.AssertFunction(call.Argument(0))
		if !ok {
			throwType(vm, "pm.response.headers.each: a function is required")
		}
		for _, k := range names {
			pair := vm.NewObject()
			pair.Set("key", k)
			pair.Set("value", strings.Join(headers[k], ", "))
			if _, err := fn(goja.Undefined(), pair); err != nil {
				panic(err)
			}
		}
		return goja.Undefined()
	})
	return obj
}

// responseAssertions implements pm.response.to.*: the handful of response
// assertions Postman scripts use most, and nothing that would silently pass.
func responseAssertions(vm *goja.Runtime, resp *ResponseCtx) *goja.Object {
	to := vm.NewObject()

	have := vm.NewObject()
	have.Set("status", func(call goja.FunctionCall) goja.Value {
		want := int(call.Argument(0).ToInteger())
		if resp.Code != want {
			throwAssertion(vm, fmt.Sprintf("expected response to have status code %d but got %d", want, resp.Code))
		}
		return goja.Undefined()
	})
	have.Set("header", func(call goja.FunctionCall) goja.Value {
		name := call.Argument(0).String()
		_, joined, found := findHeader(resp.Headers, name)
		if !found {
			throwAssertion(vm, fmt.Sprintf("expected response to have header %q", name))
			return goja.Undefined()
		}
		if len(call.Arguments) > 1 {
			want := call.Argument(1).String()
			if joined != want {
				throwAssertion(vm, fmt.Sprintf("expected header %q to equal %q but got %q", name, want, joined))
			}
		}
		return goja.Undefined()
	})
	to.Set("have", have)

	// Postman writes these without parentheses (pm.response.to.be.ok), so they are
	// assertion *properties*: reading one runs the check.
	be := vm.NewObject()
	beOk := func() {
		if resp.Code < 200 || resp.Code > 299 {
			throwAssertion(vm, fmt.Sprintf("expected response to be ok (2xx) but got %d", resp.Code))
		}
	}
	defineGetter(vm, be, "ok", func(goja.FunctionCall) goja.Value {
		beOk()
		return be
	})
	defineGetter(vm, be, "success", func(goja.FunctionCall) goja.Value {
		beOk()
		return be
	})
	beStatus := func(test func(int) bool, phrase string) func(goja.FunctionCall) goja.Value {
		return func(goja.FunctionCall) goja.Value {
			if !test(resp.Code) {
				throwAssertion(vm, fmt.Sprintf("expected response %s but got %d", phrase, resp.Code))
			}
			return be
		}
	}
	defineGetter(vm, be, "error", beStatus(func(c int) bool { return c >= 400 }, "to be an error (4xx/5xx)"))
	defineGetter(vm, be, "clientError", beStatus(func(c int) bool { return c >= 400 && c <= 499 }, "to be a client error (4xx)"))
	defineGetter(vm, be, "serverError", beStatus(func(c int) bool { return c >= 500 }, "to be a server error (5xx)"))
	defineGetter(vm, be, "json", func(goja.FunctionCall) goja.Value {
		var parsed any
		if err := json.Unmarshal([]byte(resp.Body), &parsed); err != nil {
			throwAssertion(vm, "expected response body to be valid JSON")
		}
		return be
	})
	defineGetter(vm, be, "text", func(goja.FunctionCall) goja.Value {
		_, contentType, found := findHeader(resp.Headers, "Content-Type")
		if !found || !strings.HasPrefix(strings.ToLower(contentType), "text/") {
			throwAssertion(vm, fmt.Sprintf("expected response to be text but content-type is %q", contentType))
		}
		return be
	})
	to.Set("be", be)

	return to
}

func findHeader(headers map[string][]string, name string) ([]string, string, bool) {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v, strings.Join(v, ", "), true
		}
	}
	return nil, "", false
}
