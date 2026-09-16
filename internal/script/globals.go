package script

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/dop251/goja"
)

// installCompatGlobals adds the handful of non-ECMAScript globals a Postman
// script assumes it can use: atob / btoa and TextEncoder / TextDecoder.
//
// They exist for the same reason the tweetnacl shim does — a script copied out
// of Postman must not have to be rewritten before it can be pasted in. The
// base64 helpers are also the reason `nacl.sign.keyPair.fromSeed(atob(key))`
// style scripts work at all: without atob, every key conversion becomes a manual
// loop over String.fromCharCode.
//
// Deliberately not provided: Buffer, setTimeout, fetch, XMLHttpRequest, and the
// Node modules those come from. Those reach outside the values a request was
// handed, which is the line this sandbox draws.
func (r *Runtime) installCompatGlobals() {
	vm := r.vm

	// atob(s): base64 -> binary (latin1) string, like the browser.
	//
	// Tolerant on purpose, unlike a browser: whitespace is ignored and missing
	// padding is re-added, because a base64 key pasted into a variable often
	// arrives wrapped or stripped. Anything else is an error, never a guess.
	setGlobal(vm, "atob", func(call goja.FunctionCall) goja.Value {
		arg := call.Argument(0)
		if arg == nil || goja.IsUndefined(arg) || goja.IsNull(arg) {
			// The usual cause is a variable that does not exist. Reporting that
			// plainly matters: "invalid base64 input" would send the reader off
			// to inspect a key that was never the problem.
			throwNamed(vm, "InvalidCharacterError",
				"atob: expected a string, got %s (an unset pm.variables entry?)", describe(arg))
		}
		src := arg.String()
		raw, err := decodeBase64Lenient(src)
		if err != nil {
			throwNamed(vm, "InvalidCharacterError", "atob: %v", atobInputError(src, err))
		}
		s, err := EncodeBytes(raw, "latin1")
		if err != nil {
			throwNamed(vm, "InvalidCharacterError", "atob: %v", err)
		}
		return vm.ToValue(s)
	})

	// btoa(s): binary (latin1) string -> base64. A string holding anything
	// above U+00FF cannot be represented as bytes, so it throws — btoa is not
	// a UTF-8 encoder, and silently mangling a UTF-8 signature there is exactly
	// the bug that is hard to see.
	setGlobal(vm, "btoa", func(call goja.FunctionCall) goja.Value {
		raw, err := DecodeString(call.Argument(0).String(), "latin1")
		if err != nil {
			throwNamed(vm, "InvalidCharacterError", "btoa: %v", err)
		}
		return vm.ToValue(base64.StdEncoding.EncodeToString(raw))
	})

	defineConstructor(vm, "TextEncoder", func(goja.FunctionCall) goja.Value {
		return textEncoderObject(vm)
	})
	defineConstructor(vm, "TextDecoder", func(call goja.FunctionCall) goja.Value {
		return textDecoderObject(vm, optionalString(call.Argument(0)))
	})
}

// atobInputError explains why atob rejected its input *without repeating the
// input*: the value is usually a signing key, and this message ends up in the
// response body and in the audit log, so quoting it would be a leak. It carries
// what is needed to find the mistake instead — how long the value was, and which
// of the handful of realistic mistakes this one is.
func atobInputError(src string, err error) string {
	msg := fmt.Sprintf("%v (%d chars)", err, len(stripBase64Space(src)))
	if hint := atobInputHint(src); hint != "" {
		return msg + "; " + hint
	}
	return msg
}

// atobInputHint names the reasons a pasted base64 value fails, in the order a
// script author runs into them.
func atobInputHint(src string) string {
	clean := stripBase64Space(src)
	if clean == "" {
		return "the input is empty"
	}
	if strings.Contains(src, "{{") {
		// Scripts run before variable resolution, so a placeholder arrives here
		// verbatim. Saying so is the whole point: the author would otherwise hunt
		// for a typo in a key that is perfectly fine.
		return "a {{...}} placeholder is not expanded inside a script (pre-request scripts run " +
			"before variable resolution); read a plain variable with pm.variables.get('NAME') — " +
			"secrets are never available to scripts"
	}
	if strings.ContainsAny(clean, "-_") {
		return "this looks like base64url; atob expects standard base64 ('+' and '/')"
	}
	if i := firstInvalidBase64Byte(clean); i >= 0 {
		hint := fmt.Sprintf("character %d is outside the base64 alphabet (A-Z a-z 0-9 + /)", i+1)
		if isMaskedValue(clean) {
			// The value a shared Task.md / collection prints instead of a key. Say
			// so: "character 1 is wrong" alone leaves the reader hunting for a typo
			// in a key that is simply not there.
			hint += "; a run of asterisks is the mask a shared script prints in place of a key, not the key " +
				"itself — read the real value with pm.variables.get('NAME')"
		}
		return hint
	}
	if len(clean)%4 == 1 {
		return "the length is 1 more than a multiple of 4, which no amount of padding makes valid"
	}
	return ""
}

// firstInvalidBase64Byte returns the index of the first byte outside the
// standard base64 alphabet, or -1 when every byte is acceptable.
func firstInvalidBase64Byte(s string) int {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/', c == '=':
		default:
			return i
		}
	}
	return -1
}

// isMaskedValue reports whether the value is nothing but asterisks: the mask a
// shared collection (Task.md included) prints where a key used to be, and the
// reason a verbatim copy of such a script signs nothing.
func isMaskedValue(s string) bool {
	return len(s) >= 2 && strings.Trim(s, "*") == ""
}

// decodeBase64Lenient decodes standard base64, ignoring whitespace and
// tolerating missing padding. An empty (or whitespace-only) input is an error:
// a browser hands an empty string straight back from atob, but the only way a
// signing script reaches this with nothing is a variable that was never set —
// and a zero-length seed would otherwise fail much later, with a message about
// the key length instead of the variable that was missing.
func decodeBase64Lenient(s string) ([]byte, error) {
	clean := stripBase64Space(s)
	if clean == "" {
		return nil, errors.New("invalid base64 input")
	}
	if b, err := base64.StdEncoding.DecodeString(clean); err == nil {
		return b, nil
	}
	if rem := len(clean) % 4; rem != 0 {
		clean += strings.Repeat("=", 4-rem)
	}
	b, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 input")
	}
	return b, nil
}

// optionalString reads an optional argument the way the DOM does: a missing or
// undefined argument is the empty string ("no encoding specified"), not the
// literal "undefined" a bare Argument(0).String() would hand back.
func optionalString(v goja.Value) string {
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return ""
	}
	return v.String()
}

// textEncoderObject is `new TextEncoder()`: UTF-8 only, which is the only
// encoding TextEncoder is allowed to support in the first place.
func textEncoderObject(vm *goja.Runtime) *goja.Object {
	enc := vm.NewObject()
	enc.Set("encoding", "utf-8")
	enc.Set("encode", func(call goja.FunctionCall) goja.Value {
		return NewBytes(vm, []byte(call.Argument(0).String()))
	})
	// encodeInto(src, dest) is part of the spec but rare in scripts; leaving it
	// undefined means a script that calls it fails loudly instead of getting
	// half a conversion.
	return enc
}

// textDecoderObject is `new TextDecoder([label])`. UTF-8 (the default) and
// latin1 are supported; any other label throws, because a decoder that quietly
// falls back to UTF-8 turns a wrong-encoding bug into mojibake.
func textDecoderObject(vm *goja.Runtime, label string) *goja.Object {
	enc := normalizeEncoding(label)
	switch enc {
	case "", "utf-8", "utf8", "unicode-1-1-utf-8":
		enc = "utf-8"
	case "latin1", "binary", "iso-8859-1":
		enc = "latin1"
	default:
		throwNamed(vm, "RangeError", "TextDecoder: unsupported encoding %q (utf-8 and latin1 only)", label)
	}

	dec := vm.NewObject()
	dec.Set("encoding", enc)
	dec.Set("decode", func(call goja.FunctionCall) goja.Value {
		v := call.Argument(0)
		if v == nil || goja.IsUndefined(v) {
			return vm.ToValue("")
		}
		raw, err := Bytes(vm, v)
		if err != nil {
			throwType(vm, "TextDecoder.decode: %v", err)
		}
		if enc == "latin1" {
			s, err := EncodeBytes(raw, "latin1")
			if err != nil {
				throwType(vm, "TextDecoder.decode: %v", err)
			}
			return vm.ToValue(s)
		}
		if !utf8.Valid(raw) {
			// Non-fatal mode (the default) replaces bad sequences rather than
			// throwing, which is what a script reading a text/plain body wants.
			return vm.ToValue(strings.ToValidUTF8(string(raw), "\uFFFD"))
		}
		return vm.ToValue(string(raw))
	})
	dec.Set("toString", func(goja.FunctionCall) goja.Value {
		return vm.ToValue("[object TextDecoder]")
	})
	return dec
}

// throwNamed raises a JS Error with an explicit `name`, the way the DOM helpers
// do (atob/btoa throw InvalidCharacterError, TextDecoder throws RangeError).
// These messages are read by whoever is fixing a request, so naming the failure
// precisely matters more than matching a browser's stack trace.
func throwNamed(vm *goja.Runtime, name, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	errObj, err := vm.New(vm.Get("Error"), vm.ToValue(msg))
	if err != nil || errObj == nil {
		panic(vm.ToValue(msg))
	}
	if serr := errObj.Set("name", name); serr != nil {
		panic(vm.ToValue(msg))
	}
	panic(errObj)
}

// setGlobal installs a native function as a global.
func setGlobal(vm *goja.Runtime, name string, fn func(goja.FunctionCall) goja.Value) {
	if err := vm.Set(name, vm.ToValue(fn)); err != nil {
		panic("script: install " + name + ": " + err.Error())
	}
}

// defineConstructor installs `name` as a global usable both as `new Name(...)`
// and as a bare call.
//
// A Go function can be one or the other in goja, not both (a
// func(FunctionCall) Value is callable, a func(ConstructorCall) *Object is a
// constructor), so a one-line JS wrapper does the bridging: a JS function is
// callable and constructible, and because it returns an object the `new` form
// yields that object instead of a fresh `this`.
//
// The wrapper forwards its arguments (via `arguments`, since the arity is not
// known here), so `new TextDecoder("latin1")` reaches the factory instead of
// arriving as an undefined label.
//
// The returned object is not an instance of the wrapper's prototype, which only
// matters for an `x instanceof TextEncoder` check — rare enough not to buy a
// second JS object hierarchy for.
func defineConstructor(vm *goja.Runtime, name string, factory func(goja.FunctionCall) goja.Value) {
	tmp := "__postlite_ctor_" + name
	if err := vm.Set(tmp, vm.ToValue(factory)); err != nil {
		panic("script: install " + name + ": " + err.Error())
	}
	fn, err := vm.RunString("(function (factory) { return function " + name + "() { return factory.apply(undefined, arguments); }; })(" + tmp + ")")
	if err != nil {
		panic("script: build " + name + ": " + err.Error())
	}
	if err := vm.Set(name, fn); err != nil {
		panic("script: install " + name + ": " + err.Error())
	}
	_ = vm.GlobalObject().Delete(tmp)
}
