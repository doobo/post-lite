package script

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/dop251/goja"
)

// ErrNotBytes is returned for a value that cannot be read as a byte sequence at
// all (a number, a plain object without a length, null, ...).
var ErrNotBytes = errors.New("expected a byte sequence (Uint8Array / ArrayBuffer / number[] / string)")

// maxBytes caps the array-like path in Bytes so a hostile script cannot ask for
// a gigabyte-long slice; every legit nacl/crypto input is a few hundred bytes.
const maxBytes = 64 << 20

// Bytes reads a JS value as bytes. It accepts the shapes a Postman script
// realistically hands to a crypto call:
//
//	Uint8Array / Uint8ClampedArray / DataView  (backed by the same memory)
//	ArrayBuffer
//	Array<number> / any number-like object with a numeric length
//	other typed arrays (Uint16Array, Float64Array, ...) via ToUint8 per element
//	string (UTF-8)
//
// Being lenient here is deliberate: tweetnacl in Postman throws for a string,
// but accepting one means both the raw-string and the
// utf8ToUint8Array(signContent) spellings of an old script keep working.
//
// The returned slice aliases the JS buffer when the input was a typed array, so
// copy it before it has to outlive the call.
func Bytes(vm *goja.Runtime, v goja.Value) ([]byte, error) {
	if v == nil || goja.IsNull(v) || goja.IsUndefined(v) {
		return nil, fmt.Errorf("%w: got %s", ErrNotBytes, describe(v))
	}

	exported, err := safeExport(v)
	if err != nil {
		return nil, err
	}
	switch b := exported.(type) {
	case string:
		return []byte(b), nil
	case []byte:
		return b, nil
	case goja.ArrayBuffer:
		return b.Bytes(), nil
	case []any:
		return numbersToBytes(b)
	}

	// Other typed arrays export as a numeric slice of their element type.
	if rv := reflect.ValueOf(exported); rv.Kind() == reflect.Slice && isNumericKind(rv.Type().Elem().Kind()) {
		out := make([]byte, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			out[i] = toUint8(rv.Index(i))
		}
		return out, nil
	}

	// Last resort: an array-like object ({0:1, 1:2, length:2}, arguments, ...).
	// A function has a length too (its arity), so it must be excluded here.
	if obj, ok := v.(*goja.Object); ok {
		if _, isFunc := goja.AssertFunction(v); !isFunc {
			if b, ok := arrayLikeBytes(obj); ok {
				return b, nil
			}
		}
	}

	return nil, fmt.Errorf("%w: got %s", ErrNotBytes, describe(v))
}

// arrayLikeBytes reads {0: n, ..., length: n} objects.
func arrayLikeBytes(obj *goja.Object) ([]byte, bool) {
	lv := obj.Get("length")
	if lv == nil {
		return nil, false
	}
	n := int(lv.ToInteger())
	if n < 0 || n > maxBytes {
		return nil, false
	}
	out := make([]byte, n)
	for i := range out {
		item := obj.Get(strconv.Itoa(i))
		if item == nil {
			continue
		}
		out[i] = toUint8Value(item)
	}
	return out, true
}

// NewBytes wraps Go bytes in a Uint8Array, so a signature computed in Go looks
// like what a script expects from tweetnacl (indexing, .length, and being
// accepted by any base64 helper the script already has).
//
// The returned Uint8Array shares the backing array instead of copying it; call
// it with a slice you are not going to reuse.
func NewBytes(vm *goja.Runtime, b []byte) goja.Value {
	if b == nil {
		b = []byte{}
	}
	if ctor, ok := goja.AssertConstructor(vm.Get("Uint8Array")); ok {
		if obj, err := ctor(nil, vm.ToValue(vm.NewArrayBuffer(b))); err == nil {
			return obj
		}
	}
	// No Uint8Array (exotic runtime): a wrapped Go slice is still byte-readable
	// by Bytes(), it just lacks the typed-array methods.
	return vm.ToValue(b)
}

// DecodeString turns a JS string into bytes using the named encoding.
//
// Supported: "utf8"/"utf-8"/"" (default), "base64", "base64url", "hex",
// "latin1"/"binary". Anything else is an error, never a silent guess.
func DecodeString(s, encoding string) ([]byte, error) {
	switch normalizeEncoding(encoding) {
	case "", "utf8", "utf-8":
		return []byte(s), nil
	case "base64":
		b, err := base64.StdEncoding.DecodeString(stripBase64Space(s))
		if err != nil {
			return nil, fmt.Errorf("invalid base64 input: %w", err)
		}
		return b, nil
	case "base64url":
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
		if err != nil {
			return nil, fmt.Errorf("invalid base64url input: %w", err)
		}
		return b, nil
	case "hex":
		b, err := hex.DecodeString(stripBase64Space(s))
		if err != nil {
			return nil, fmt.Errorf("invalid hex input: %w", err)
		}
		return b, nil
	case "latin1", "binary":
		out := make([]byte, 0, len(s))
		for _, r := range s {
			if r > 0xff {
				return nil, fmt.Errorf("invalid latin1 input: %q is not a single byte", r)
			}
			out = append(out, byte(r))
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported input encoding %q", encoding)
	}
}

// EncodeBytes is the inverse of DecodeString. It accepts the same names plus
// "bytes"/"uint8array"/"raw" as a marker for "hand the caller the raw
// Uint8Array" — sign() checks that marker before calling here, so reaching this
// function with it is an error.
func EncodeBytes(b []byte, encoding string) (string, error) {
	switch normalizeEncoding(encoding) {
	case "", "utf8", "utf-8":
		if !utf8.Valid(b) {
			return "", errors.New("bytes are not valid UTF-8")
		}
		return string(b), nil
	case "base64":
		return base64.StdEncoding.EncodeToString(b), nil
	case "base64url":
		return base64.RawURLEncoding.EncodeToString(b), nil
	case "hex":
		return hex.EncodeToString(b), nil
	case "latin1", "binary":
		runes := make([]rune, len(b))
		for i, c := range b {
			runes[i] = rune(c)
		}
		return string(runes), nil
	default:
		return "", fmt.Errorf("unsupported output encoding %q", encoding)
	}
}

// isRawEncoding reports whether an output encoding asks for the raw bytes
// instead of a string.
func isRawEncoding(encoding string) bool {
	switch normalizeEncoding(encoding) {
	case "bytes", "byte", "uint8array", "uint8clampedarray", "raw", "array":
		return true
	}
	return false
}

func normalizeEncoding(encoding string) string {
	return strings.ToLower(strings.TrimSpace(encoding))
}

// stripBase64Space removes the whitespace that Postman scripts like to wrap
// base64 and hex blobs in.
func stripBase64Space(s string) string {
	if !strings.ContainsAny(s, " \t\r\n") {
		return s
	}
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, s)
}

// safeExport calls Export() with a recover, because exporting a value that
// throws (a getter, a revoked proxy) panics with a goja exception.
func safeExport(v goja.Value) (out any, err error) {
	defer func() {
		if x := recover(); x != nil {
			out, err = nil, fmt.Errorf("%w: %v", ErrNotBytes, x)
		}
	}()
	return v.Export(), nil
}

func numbersToBytes(items []any) ([]byte, error) {
	out := make([]byte, len(items))
	for i, it := range items {
		b, ok := numericToByte(it)
		if !ok {
			return nil, fmt.Errorf("%w: element %d is %T", ErrNotBytes, i, it)
		}
		out[i] = b
	}
	return out, nil
}

// toUint8 converts a Go number to a byte with JS ToUint8 semantics
// (NaN and out-of-range values wrap, exactly like `new Uint8Array([300])`).
func toUint8(v reflect.Value) byte {
	switch v.Kind() {
	case reflect.Float32, reflect.Float64:
		return byte(int64(v.Float()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return byte(v.Int())
	default:
		return byte(v.Uint())
	}
}

func toUint8Value(v goja.Value) byte {
	switch n := v.Export().(type) {
	case string:
		// A JS numeric string keeps JS coercion semantics.
		f, err := strconv.ParseFloat(n, 64)
		if err != nil {
			return 0
		}
		return byte(int64(f))
	default:
		if n == nil {
			return 0
		}
		if b, ok := numericToByte(n); ok {
			return b
		}
		return 0
	}
}

func numericToByte(v any) (byte, bool) {
	switch n := v.(type) {
	case int:
		return byte(n), true
	case int8:
		return byte(n), true
	case int16:
		return byte(n), true
	case int32:
		return byte(n), true
	case int64:
		return byte(n), true
	case uint:
		return byte(n), true
	case uint8:
		return n, true
	case uint16:
		return byte(n), true
	case uint32:
		return byte(n), true
	case uint64:
		return byte(n), true
	case float32:
		return byte(int64(n)), true
	case float64:
		return byte(int64(n)), true
	}
	return 0, false
}

func isNumericKind(k reflect.Kind) bool {
	switch k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	}
	return false
}

func describe(v goja.Value) string {
	if v == nil {
		return "undefined"
	}
	if o, ok := v.(*goja.Object); ok {
		if cls := o.ClassName(); cls != "" && cls != "Object" {
			return cls
		}
	}
	return v.String()
}
