package script

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"

	"github.com/dop251/goja"
)

// expectObject implements the chai subset Postman scripts actually use:
//
//	pm.expect(pm.response.code).to.equal(200);
//	pm.expect(pm.response.json().items).to.be.an('array').that.is.not.empty;
//	pm.expect(body).to.have.property('token').that.is.a('string');
//	pm.expect(text).to.include('ok').and.to.match(/^OK/i);
//
// Chainers (to, be, have, and, ...) are no-ops, not / deep are modifiers, and
// the rest are assertions. A failure throws an AssertionError, which pm.test
// records as a failed test instead of aborting the script — the same contract
// Postman has.
//
// Deliberately absent: the wider chai surface (.throw, .closeTo, .keys, ...).
// An unsupported call is a TypeError rather than a silent no-op, so a test can
// never pass because an assertion quietly did nothing.
func expectObject(vm *goja.Runtime, raw goja.Value) *goja.Object {
	return newExpectation(vm, raw, false, false).object()
}

type expectation struct {
	vm     *goja.Runtime
	raw    goja.Value
	value  any // exported form of raw, for value comparisons
	negate bool
	deep   bool
}

func newExpectation(vm *goja.Runtime, raw goja.Value, negate, deep bool) *expectation {
	exported, _ := safeExport(raw)
	return &expectation{vm: vm, raw: raw, value: exported, negate: negate, deep: deep}
}

func (e *expectation) object() *goja.Object {
	obj := e.vm.NewObject()

	// Modifiers return a new expectation so they can appear anywhere in the
	// chain: .to.not.be.ok, .to.be.deep.equal(x), .deep.not.equal(y).
	defineGetter(e.vm, obj, "not", func(goja.FunctionCall) goja.Value {
		return newExpectation(e.vm, e.raw, !e.negate, e.deep).object()
	})
	defineGetter(e.vm, obj, "deep", func(goja.FunctionCall) goja.Value {
		return newExpectation(e.vm, e.raw, e.negate, true).object()
	})

	// Chainers are properties in chai, so they are getters returning the same
	// expectation object.
	for _, name := range []string{
		"to", "be", "been", "is", "that", "which", "and", "has", "have", "with",
		"at", "of", "same", "but", "does", "still", "also",
	} {
		defineGetter(e.vm, obj, name, func(goja.FunctionCall) goja.Value { return obj })
	}

	// Property-style assertions: reading them asserts (chai's design).
	for _, pa := range []struct {
		name   string
		check  func() bool
		phrase string
	}{
		{"ok", func() bool { return isTruthy(e.raw) }, "to be truthy"},
		{"true", func() bool { v, ok := e.value.(bool); return ok && v }, "to be true"},
		{"false", func() bool { v, ok := e.value.(bool); return ok && !v }, "to be false"},
		{"null", func() bool { return goja.IsNull(e.raw) }, "to be null"},
		{"undefined", func() bool { return goja.IsUndefined(e.raw) }, "to be undefined"},
		{"NaN", func() bool { n, ok := toFloat(e.value); return ok && math.IsNaN(n) }, "to be NaN"},
		{"exist", func() bool { return !goja.IsNull(e.raw) && !goja.IsUndefined(e.raw) }, "to exist"},
		{"empty", func() bool { return lengthOf(e.value) == 0 }, "to be empty"},
	} {
		pa := pa
		defineGetter(e.vm, obj, pa.name, func(goja.FunctionCall) goja.Value {
			e.check(pa.check(), pa.phrase)
			return obj
		})
	}

	// Method assertions.
	obj.Set("equal", func(call goja.FunctionCall) goja.Value {
		want := call.Argument(0)
		same := sameObject(e.raw, want) || equalValues(e.value, mustExport(want), e.deep)
		e.check(same, "to equal "+jsInspect(want))
		return obj
	})
	obj.Set("equals", obj.Get("equal"))
	obj.Set("eq", obj.Get("equal"))
	obj.Set("eql", func(call goja.FunctionCall) goja.Value {
		want := call.Argument(0)
		e.check(jsDeepEqual(e.value, mustExport(want), 0), "to deeply equal "+jsInspect(want))
		return obj
	})
	obj.Set("eqls", obj.Get("eql"))

	for _, ta := range []struct {
		names  []string
		test   func(delta float64) bool
		phrase string
	}{
		{[]string{"above", "gt", "greaterThan"}, func(d float64) bool { return d > 0 }, "to be above"},
		{[]string{"below", "lt", "lessThan"}, func(d float64) bool { return d < 0 }, "to be below"},
		{[]string{"least", "gte", "atLeast"}, func(d float64) bool { return d >= 0 }, "to be at least"},
		{[]string{"most", "lte", "atMost"}, func(d float64) bool { return d <= 0 }, "to be at most"},
	} {
		ta := ta
		fn := func(call goja.FunctionCall) goja.Value {
			want := call.Argument(0)
			limit, ok := toFloat(mustExport(want))
			if !ok {
				throwType(e.vm, "pm.expect: %s needs a number, got %s", ta.phrase, typeName(want))
			}
			got, isNum := toFloat(e.value)
			e.check(isNum && ta.test(got-limit), ta.phrase+" "+jsInspect(want))
			return obj
		}
		for _, n := range ta.names {
			obj.Set(n, fn)
		}
	}

	// a / an: a chainer when used bare, an assertion when called.
	checkType := func(call goja.FunctionCall) goja.Value {
		want := call.Argument(0).String()
		e.check(typeName(e.raw) == want, "to be a "+want)
		return obj
	}
	obj.Set("a", checkType)
	obj.Set("an", checkType)

	obj.Set("within", func(call goja.FunctionCall) goja.Value {
		lo, lok := toFloat(mustExport(call.Argument(0)))
		hi, hok := toFloat(mustExport(call.Argument(1)))
		if !lok || !hok {
			throwType(e.vm, "pm.expect.within: two numbers are required")
		}
		v, ok := toFloat(e.value)
		e.check(ok && v >= lo && v <= hi, fmt.Sprintf("to be within %v..%v", lo, hi))
		return obj
	})

	include := func(call goja.FunctionCall) goja.Value {
		want := call.Argument(0)
		e.check(containsValue(e.value, mustExport(want)), "to include "+jsInspect(want))
		return obj
	}
	obj.Set("include", include)
	obj.Set("includes", include)
	obj.Set("contain", include)
	obj.Set("contains", include)

	obj.Set("match", func(call goja.FunctionCall) goja.Value {
		s, ok := e.value.(string)
		if !ok {
			throwType(e.vm, "pm.expect.match: %s is not a string", jsInspect(e.raw))
		}
		re, ok := call.Argument(0).(*goja.Object)
		if !ok {
			throwType(e.vm, "pm.expect.match: a RegExp is required")
		}
		test, ok := goja.AssertFunction(re.Get("test"))
		if !ok {
			throwType(e.vm, "pm.expect.match: a RegExp is required")
		}
		res, err := test(re, e.vm.ToValue(s))
		if err != nil {
			panic(err)
		}
		e.check(res.ToBoolean(), "to match "+re.String())
		return obj
	})

	lengthOfAssert := func(call goja.FunctionCall) goja.Value {
		want := int(call.Argument(0).ToInteger())
		e.check(lengthOf(e.value) == want, fmt.Sprintf("to have a length of %d", want))
		return obj
	}
	obj.Set("lengthOf", lengthOfAssert)
	obj.Set("length", lengthOfAssert)

	property := func(call goja.FunctionCall) goja.Value {
		name := call.Argument(0).String()
		got, found := propertyOf(e.raw, e.value, name)
		if len(call.Arguments) > 1 {
			want := call.Argument(1)
			e.check(found && equalValues(got, mustExport(want), e.deep),
				"to have property "+quote(name)+" equal to "+jsInspect(want))
			return obj
		}
		e.check(found, "to have property "+quote(name))
		return obj
	}
	obj.Set("property", property)
	obj.Set("ownProperty", property)

	obj.Set("oneOf", func(call goja.FunctionCall) goja.Value {
		items, ok := mustExport(call.Argument(0)).([]any)
		if !ok {
			throwType(e.vm, "pm.expect.oneOf: an array is required")
		}
		hit := false
		for _, item := range items {
			if equalValues(e.value, item, e.deep) {
				hit = true
				break
			}
		}
		e.check(hit, "to be one of "+jsInspect(call.Argument(0)))
		return obj
	})

	obj.Set("satisfy", func(call goja.FunctionCall) goja.Value {
		fn, ok := goja.AssertFunction(call.Argument(0))
		if !ok {
			throwType(e.vm, "pm.expect.satisfy: a function is required")
		}
		res, err := fn(goja.Undefined(), e.raw)
		if err != nil {
			panic(err)
		}
		e.check(res.ToBoolean(), "to satisfy the given predicate")
		return obj
	})

	return obj
}

// check throws an AssertionError when the assertion did not hold (or held while
// negated), with a message that reads like chai's: "expected 500 to equal 200".
func (e *expectation) check(ok bool, phrase string) {
	if ok != e.negate {
		return
	}
	not := ""
	if e.negate {
		not = "not "
	}
	throwAssertion(e.vm, fmt.Sprintf("expected %s %s%s", jsInspect(e.raw), not, phrase))
}

// throwAssertion throws a JS AssertionError, the type pm.test recognises.
func throwAssertion(vm *goja.Runtime, message string) {
	errObj, err := vm.New(vm.Get("Error"), vm.ToValue(message))
	if err != nil || errObj == nil {
		panic(vm.ToValue(message))
	}
	if serr := errObj.Set("name", "AssertionError"); serr != nil {
		panic(vm.ToValue(message))
	}
	panic(errObj)
}

/* ---------- value helpers ---------- */

// sameObject reports whether two JS values are the very same object, which is
// what chai's non-deep equality means for objects and arrays.
func sameObject(a, b goja.Value) bool {
	oa, ok := a.(*goja.Object)
	if !ok {
		return false
	}
	ob, ok := b.(*goja.Object)
	return ok && oa == ob
}

// equalValues compares exported JS values: numbers by value (1 === 1.0),
// primitives strictly, containers structurally (only when deep).
func equalValues(a, b any, deep bool) bool {
	if af, aok := toFloat(a); aok {
		bf, bok := toFloat(b)
		return bok && af == bf
	}
	switch av := a.(type) {
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	case nil:
		return b == nil
	}
	if !deep {
		return false
	}
	return jsDeepEqual(a, b, 0)
}

// jsDeepEqual backs .eql / .deep.equal and .include on arrays and objects.
func jsDeepEqual(a, b any, depth int) bool {
	if depth > 64 {
		return false
	}
	if af, aok := toFloat(a); aok {
		bf, bok := toFloat(b)
		return bok && af == bf
	}
	switch av := a.(type) {
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	case nil:
		return b == nil
	case []byte:
		bv, ok := b.([]byte)
		return ok && string(av) == string(bv)
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !jsDeepEqual(av[i], bv[i], depth+1) {
				return false
			}
		}
		return true
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for k, v := range av {
			other, present := bv[k]
			if !present || !jsDeepEqual(v, other, depth+1) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(a, b)
}

// containsValue implements .include: substring for strings, membership for
// arrays, subset for objects.
func containsValue(container, want any) bool {
	switch cv := container.(type) {
	case string:
		ws, ok := want.(string)
		return ok && strings.Contains(cv, ws)
	case []byte:
		ws, ok := want.(string)
		return ok && strings.Contains(string(cv), ws)
	case []any:
		for _, item := range cv {
			if jsDeepEqual(item, want, 0) {
				return true
			}
		}
		return false
	case map[string]any:
		wm, ok := want.(map[string]any)
		if !ok {
			return false
		}
		for k, v := range wm {
			found, present := cv[k]
			if !present || !jsDeepEqual(found, v, 0) {
				return false
			}
		}
		return true
	}
	return false
}

// propertyOf resolves a property for .property(): object keys, plus the index /
// length shortcuts chai allows on arrays and strings.
func propertyOf(raw goja.Value, exported any, name string) (any, bool) {
	if m, ok := exported.(map[string]any); ok {
		v, found := m[name]
		return v, found
	}
	if obj, ok := raw.(*goja.Object); ok {
		v := obj.Get(name)
		if v == nil {
			return nil, false
		}
		exported, _ := safeExport(v)
		return exported, true
	}
	return nil, false
}

// lengthOf returns -1 for values that have no length, so `.length(n)` on a
// number fails instead of comparing against a bogus 0.
func lengthOf(exported any) int {
	switch v := exported.(type) {
	case string:
		return len(v)
	case []byte:
		return len(v)
	case []any:
		return len(v)
	case map[string]any:
		return len(v)
	}
	return -1
}

// typeName is what `.a('string')` compares against, following chai's names
// closely enough for the assertions people write ("array", "object", "number").
func typeName(raw goja.Value) string {
	if raw == nil || goja.IsUndefined(raw) {
		return "undefined"
	}
	if goja.IsNull(raw) {
		return "null"
	}
	exported, _ := safeExport(raw)
	switch exported.(type) {
	case string:
		return "string"
	case bool:
		return "boolean"
	case []any, []byte:
		return "array"
	case map[string]any:
		if obj, ok := raw.(*goja.Object); ok && obj.ClassName() == "Array" {
			return "array"
		}
		return "object"
	}
	if _, ok := toFloat(exported); ok {
		return "number"
	}
	if obj, ok := raw.(*goja.Object); ok {
		if _, isFunc := goja.AssertFunction(obj); isFunc {
			return "function"
		}
		if obj.ClassName() == "Array" {
			return "array"
		}
	}
	return "object"
}

func isTruthy(v goja.Value) bool { return v != nil && v.ToBoolean() }

func toFloat(v any) (float64, bool) {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return 0, false
	}
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(rv.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return float64(rv.Uint()), true
	case reflect.Float32, reflect.Float64:
		return rv.Float(), true
	}
	return 0, false
}

func mustExport(v goja.Value) any {
	exported, _ := safeExport(v)
	return exported
}

// jsInspect renders a value the way an assertion message needs it: strings
// quoted, containers as JSON, everything else as its own text.
func jsInspect(v goja.Value) string {
	if v == nil || goja.IsUndefined(v) {
		return "undefined"
	}
	if goja.IsNull(v) {
		return "null"
	}
	exported, _ := safeExport(v)
	switch e := exported.(type) {
	case string:
		return quote(e)
	case []byte:
		return quote(string(e))
	case map[string]any, []any:
		if raw, err := json.Marshal(exported); err == nil {
			return truncate(string(raw))
		}
	}
	return truncate(v.String())
}

func truncate(s string) string {
	if len(s) <= 160 {
		return s
	}
	return s[:160] + "..."
}

func quote(s string) string { return `"` + s + `"` }
