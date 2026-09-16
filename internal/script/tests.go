package script

import (
	"errors"
	"fmt"

	"github.com/dop251/goja"
)

// TestResult is one assertion outcome: a pm.test(name, fn) run or one
// `tests[name] = <truthy>` assignment.
type TestResult struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message,omitempty"`
}

// installTestHelpers adds pm.test, pm.expect and the legacy `tests` object.
// Test results live on the Runtime, not on the bound Env, so the pre-request and
// the post-response script of one execution accumulate into the same list, in
// the order they ran.
func (r *Runtime) installTestHelpers(pm *goja.Object) {
	pm.Set("expect", func(call goja.FunctionCall) goja.Value {
		return expectObject(r.vm, call.Argument(0))
	})
	pm.Set("test", func(call goja.FunctionCall) goja.Value {
		r.runTest(call.Argument(0).String(), call.Argument(1))
		return goja.Undefined()
	})
	// The pre-pm.test way of writing tests. Kept because migrating a collection
	// should not mean rewriting every assertion.
	if err := r.vm.Set("tests", r.legacyTests()); err != nil {
		panic("script: install tests: " + err.Error())
	}
}

// Tests returns the recorded results (pm.test and legacy tests[...]).
func (r *Runtime) Tests() []TestResult { return r.tests }

func (r *Runtime) record(res TestResult) { r.tests = append(r.tests, res) }

// runTest calls fn and records pass/fail. An exception inside fn — an
// AssertionError or a plain bug — marks that one test failed and lets the
// script continue, which is what Postman does.
func (r *Runtime) runTest(name string, fn goja.Value) {
	callable, ok := goja.AssertFunction(fn)
	if !ok {
		r.record(TestResult{Name: name, Passed: false, Message: "pm.test: the second argument must be a function"})
		return
	}
	res := TestResult{Name: name, Passed: true}
	ex := r.vm.Try(func() {
		if _, err := callable(goja.Undefined()); err != nil {
			var jsEx *goja.Exception
			if errors.As(err, &jsEx) {
				panic(jsEx)
			}
			// A Go-side error has to become a JS value, or vm.Try would drop it.
			panic(r.vm.NewGoError(err))
		}
	})
	if ex != nil {
		res.Passed = false
		res.Message = exceptionMessage(ex)
	}
	r.record(res)
}

// ErrorMessage is what a failed Run should report: the JS message for a thrown
// error, without the stack trace goja appends (or without a Go error's internals
// for a timeout).
func ErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	var ex *goja.Exception
	if errors.As(err, &ex) {
		return exceptionMessage(ex)
	}
	var interrupted *goja.InterruptedError
	if errors.As(err, &interrupted) {
		if inner := interrupted.Unwrap(); inner != nil {
			return inner.Error()
		}
	}
	return err.Error()
}

// exceptionMessage prefers the JS `message` (what an AssertionError carries)
// over the "Error: ..." rendering.
func exceptionMessage(ex *goja.Exception) string {
	v := ex.Value()
	if obj, ok := v.(*goja.Object); ok {
		if m := obj.Get("message"); m != nil && !goja.IsUndefined(m) && !goja.IsNull(m) {
			return m.String()
		}
	}
	if v == nil {
		return "test failed"
	}
	return v.String()
}

// legacyTests returns the `tests` object, backed by a Proxy so every assignment
// is recorded as a result the moment the script makes it.
func (r *Runtime) legacyTests() goja.Value {
	target := r.vm.NewObject()
	proxy := r.vm.NewProxy(target, &goja.ProxyTrapConfig{
		Get: func(t *goja.Object, prop string, _ goja.Value) goja.Value { return t.Get(prop) },
		Set: func(t *goja.Object, prop string, value goja.Value, _ goja.Value) bool {
			if err := t.Set(prop, value); err != nil {
				return false
			}
			res := TestResult{Name: prop, Passed: value.ToBoolean()}
			if !res.Passed {
				res.Message = fmt.Sprintf("tests[%q] was set to %s", prop, jsInspect(value))
			}
			r.record(res)
			return true
		},
		Has:            func(t *goja.Object, prop string) bool { return t.Get(prop) != nil },
		DeleteProperty: func(t *goja.Object, prop string) bool { return t.Delete(prop) == nil },
		OwnKeys: func(t *goja.Object) *goja.Object {
			return r.vm.ToValue(t.Keys()).(*goja.Object)
		},
	})
	return r.vm.ToValue(proxy)
}
