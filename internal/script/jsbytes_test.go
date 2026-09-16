package script

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/dop251/goja"
)

func TestBytesFromJSValues(t *testing.T) {
	vm := goja.New()
	if err := vm.Set("goBytes", func() []byte { return []byte{9, 8, 7} }); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		expr string
		want []byte
	}{
		{"new Uint8Array([1, 2, 3])", []byte{1, 2, 3}},
		{"new Uint8Array([1, 2, 3]).buffer", []byte{1, 2, 3}},
		{"new Uint8Array([1, 2, 3, 4]).subarray(1, 3)", []byte{2, 3}},
		{"new Uint8ClampedArray([255, 256, -1])", []byte{255, 255, 0}},
		{"[1, 2, 3]", []byte{1, 2, 3}},
		{"new Uint16Array([1, 300])", []byte{1, 44}},
		{"'abc'", []byte("abc")},
		{"'汉字'", []byte("汉字")},
		{"goBytes()", []byte{9, 8, 7}},
		{"({0: 1, 1: 2, length: 2})", []byte{1, 2}},
		{"({length: 0})", []byte{}},
		{"new Uint8Array([])", []byte{}},
	}
	for _, tc := range cases {
		v, err := vm.RunString(tc.expr)
		if err != nil {
			t.Fatalf("%s: %v", tc.expr, err)
		}
		got, err := Bytes(vm, v)
		if err != nil {
			t.Errorf("Bytes(%s) error: %v", tc.expr, err)
			continue
		}
		if !bytes.Equal(got, tc.want) {
			t.Errorf("Bytes(%s) = %v, want %v", tc.expr, got, tc.want)
		}
	}
}

func TestBytesRejectsNonBytes(t *testing.T) {
	vm := goja.New()
	for _, expr := range []string{"null", "undefined", "42", "'x'.length", "{}", "{a: 1}", "true", "(() => 1)"} {
		v, err := vm.RunString(expr)
		if err != nil {
			t.Fatalf("%s: %v", expr, err)
		}
		if _, err := Bytes(vm, v); !errors.Is(err, ErrNotBytes) {
			t.Errorf("Bytes(%s) error = %v, want ErrNotBytes", expr, err)
		}
	}
	if _, err := Bytes(vm, nil); !errors.Is(err, ErrNotBytes) {
		t.Errorf("Bytes(nil) error = %v, want ErrNotBytes", err)
	}
}

func TestBytesRejectsMixedArray(t *testing.T) {
	vm := goja.New()
	v, err := vm.RunString("[1, 'two']")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Bytes(vm, v); !errors.Is(err, ErrNotBytes) {
		t.Fatalf("error = %v, want ErrNotBytes", err)
	}
}

func TestNewBytesProducesUint8Array(t *testing.T) {
	rt := New()
	vm := rt.VM()
	if err := vm.Set("mk", func(b []byte) goja.Value { return NewBytes(vm, b) }); err != nil {
		t.Fatal(err)
	}
	v, err := vm.RunString(`
		const b = mk([104, 105]);
		[Object.prototype.toString.call(b), b.length, b[0], b[1], b instanceof Uint8Array].join(",")
	`)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := v.String(), "[object Uint8Array],2,104,105,true"; got != want {
		t.Fatalf("NewBytes round trip = %s, want %s", got, want)
	}
}

func TestEncodeDecodeEncodings(t *testing.T) {
	raw := []byte{0x00, 0x01, 0xfe, 0xff, 0x41}
	for _, enc := range []string{"base64", "base64url", "hex", "latin1", "binary", "utf8"} {
		s, err := EncodeBytes(raw, enc)
		if err != nil {
			if enc == "utf8" {
				continue // 0xfe is not valid UTF-8, rejected on purpose
			}
			t.Fatalf("EncodeBytes(%s): %v", enc, err)
		}
		back, err := DecodeString(s, enc)
		if err != nil {
			t.Fatalf("DecodeString(%s): %v", enc, err)
		}
		if !bytes.Equal(back, raw) {
			t.Errorf("%s round trip = %v, want %v", enc, back, raw)
		}
	}
}

func TestDecodeStringDetails(t *testing.T) {
	if b, err := DecodeString(" YWJj\n", "base64"); err != nil || string(b) != "abc" {
		t.Fatalf("base64 with whitespace = %q, %v", b, err)
	}
	if b, err := DecodeString("YWJj", ""); err != nil || string(b) != "YWJj" {
		t.Fatalf("default encoding should be utf8: %q, %v", b, err)
	}
	if _, err := DecodeString("!!!", "base64"); err == nil {
		t.Fatal("invalid base64 accepted")
	}
	if _, err := DecodeString("abc", "hex"); err == nil {
		t.Fatal("odd-length hex accepted")
	}
	if _, err := DecodeString("a", "rot13"); err == nil || !strings.Contains(err.Error(), "unsupported input encoding") {
		t.Fatalf("unexpected error for unknown encoding: %v", err)
	}
	if _, err := EncodeBytes([]byte{0xff}, "utf8"); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
	if _, err := EncodeBytes([]byte{1}, "nope"); err == nil {
		t.Fatal("unknown output encoding accepted")
	}
}

func TestDecodeStringLatin1(t *testing.T) {
	if _, err := DecodeString("日", "latin1"); err == nil {
		t.Fatal("multi-byte rune accepted as latin1")
	}
}

func TestEncodeBytesMatchesStdlib(t *testing.T) {
	raw := []byte("hello world")
	b64, err := EncodeBytes(raw, "base64")
	if err != nil {
		t.Fatal(err)
	}
	if b64 != base64.StdEncoding.EncodeToString(raw) {
		t.Fatalf("base64 = %s", b64)
	}
	h, err := EncodeBytes(raw, "hex")
	if err != nil {
		t.Fatal(err)
	}
	if h != hex.EncodeToString(raw) {
		t.Fatalf("hex = %s", h)
	}
}

func TestIsRawEncoding(t *testing.T) {
	for _, enc := range []string{"bytes", "uint8array", "RAW", " byte "} {
		if !isRawEncoding(enc) {
			t.Errorf("isRawEncoding(%q) = false", enc)
		}
	}
	for _, enc := range []string{"base64", "utf8", ""} {
		if isRawEncoding(enc) {
			t.Errorf("isRawEncoding(%q) = true", enc)
		}
	}
}
