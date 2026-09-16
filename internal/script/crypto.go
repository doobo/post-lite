package script

import (
	"crypto/ed25519"
	"fmt"

	"github.com/dop251/goja"
)

// cryptoModule builds the `pm.crypto` object. It is the "native" half of the
// two-track strategy in docs/post-lite-script.md: the same Ed25519 as the
// tweetnacl compatibility layer, without the base64/UTF-8 conversion helpers a
// script would otherwise have to bring along.
//
//	pm.crypto.ed25519.sign({seed, data, [inputEncoding], [seedEncoding], [outputEncoding]})
//	pm.crypto.ed25519.verify({publicKey | seed, data, signature, ...})
//	pm.crypto.ed25519.keyPairFromSeed({seed, ...})
//
// `seed`, `data`, `publicKey` and `signature` may be strings or byte sequences;
// a string is decoded with the matching *Encoding option. The defaults are
// picked so that the obvious thing works without any options at all:
//
//	inputEncoding     data            "utf8"
//	seedEncoding      seed            inputEncoding (one shared encoding, as in
//	                                  the doc's sample)
//	outputEncoding    result          "base64"
//	signatureEncoding signature       "base64"  (what sign() hands back)
//	publicKeyEncoding publicKey       "base64"  (what keyPairFromSeed() hands back)
//
// So a seed from a config file is the only value that normally needs an
// encoding of its own: sign({seed, seedEncoding: 'base64', data}). The output
// can be "base64", "base64url", "hex", "utf8", "latin1" or "bytes" (raw
// bytes, returned as a Uint8Array).
func cryptoModule(vm *goja.Runtime) *goja.Object {
	crypto := vm.NewObject()
	ed := vm.NewObject()

	ed.Set("sign", func(call goja.FunctionCall) goja.Value {
		const who = "pm.crypto.ed25519.sign"
		opts, err := optionsObject(who, call)
		if err != nil {
			throwType(vm, "%v", err)
		}
		seed, err := opts.fieldBytes(vm, who, "seed", "seedEncoding", ed25519.SeedSize)
		if err != nil {
			throwType(vm, "%v", err)
		}
		data, err := opts.fieldBytes(vm, who, "data", "inputEncoding", 0)
		if err != nil {
			throwType(vm, "%v", err)
		}
		sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), data)

		out := opts.optString("outputEncoding", "base64")
		if isRawEncoding(out) {
			return NewBytes(vm, sig)
		}
		s, err := EncodeBytes(sig, out)
		if err != nil {
			throwType(vm, "%s: %v", who, err)
		}
		return vm.ToValue(s)
	})

	ed.Set("verify", func(call goja.FunctionCall) goja.Value {
		const who = "pm.crypto.ed25519.verify"
		opts, err := optionsObject(who, call)
		if err != nil {
			throwType(vm, "%v", err)
		}
		data, err := opts.fieldBytes(vm, who, "data", "inputEncoding", 0)
		if err != nil {
			throwType(vm, "%v", err)
		}
		sig, err := opts.fieldBytesDefault(vm, who, "signature", "signatureEncoding", "base64", ed25519.SignatureSize)
		if err != nil {
			throwType(vm, "%v", err)
		}

		var pub ed25519.PublicKey
		if opts.has("publicKey") {
			raw, err := opts.fieldBytesDefault(vm, who, "publicKey", "publicKeyEncoding", "base64", ed25519.PublicKeySize)
			if err != nil {
				throwType(vm, "%v", err)
			}
			pub = ed25519.PublicKey(raw)
		} else {
			seed, err := opts.fieldBytes(vm, who, "seed", "seedEncoding", ed25519.SeedSize)
			if err != nil {
				throwType(vm, "%v", err)
			}
			pub = ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		}
		return vm.ToValue(ed25519.Verify(pub, data, sig))
	})

	ed.Set("keyPairFromSeed", func(call goja.FunctionCall) goja.Value {
		const who = "pm.crypto.ed25519.keyPairFromSeed"
		opts, err := optionsObject(who, call)
		if err != nil {
			throwType(vm, "%v", err)
		}
		seed, err := opts.fieldBytes(vm, who, "seed", "seedEncoding", ed25519.SeedSize)
		if err != nil {
			throwType(vm, "%v", err)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		pub := []byte(priv.Public().(ed25519.PublicKey))

		kp := vm.NewObject()
		out := opts.optString("outputEncoding", "base64")
		if isRawEncoding(out) {
			// secretKey is seed||publicKey, like tweetnacl's.
			kp.Set("publicKey", NewBytes(vm, pub))
			kp.Set("secretKey", NewBytes(vm, []byte(priv)))
			return kp
		}
		pubStr, err := EncodeBytes(pub, out)
		if err != nil {
			throwType(vm, "%s: %v", who, err)
		}
		secStr, err := EncodeBytes([]byte(priv), out)
		if err != nil {
			throwType(vm, "%s: %v", who, err)
		}
		kp.Set("publicKey", pubStr)
		kp.Set("secretKey", secStr)
		return kp
	})

	crypto.Set("ed25519", ed)
	return crypto
}

// options is one pm.crypto call's options object.
type options struct {
	obj *goja.Object
}

func optionsObject(who string, call goja.FunctionCall) (*options, error) {
	v := call.Argument(0)
	if !goja.IsUndefined(v) && !goja.IsNull(v) {
		if obj, ok := v.(*goja.Object); ok {
			return &options{obj: obj}, nil
		}
	}
	return nil, fmt.Errorf("%s: an options object is required, e.g. %s({seed: '...', data: '...'})", who, who)
}

func (o *options) has(field string) bool {
	return o.get(field) != nil
}

func (o *options) get(field string) goja.Value {
	v := o.obj.Get(field)
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return nil
	}
	return v
}

// optString reads an optional string field.
func (o *options) optString(field, def string) string {
	if v := o.get(field); v != nil {
		return v.String()
	}
	return def
}

// inputEncoding is the encoding of `data`, defaulting to UTF-8.
func (o *options) inputEncoding() string {
	return o.optString("inputEncoding", "utf8")
}

// fieldBytes reads a required field as bytes, decoding a string with
// inputEncoding (or the field's own override when it has a different default).
func (o *options) fieldBytes(vm *goja.Runtime, who, field, encField string, want int) ([]byte, error) {
	return o.fieldBytesDefault(vm, who, field, encField, "", want)
}

// fieldBytesDefault is fieldBytes with an explicit default for a field whose
// encoding is independent of inputEncoding (signature, publicKey: both default
// to base64, matching what this API outputs).
func (o *options) fieldBytesDefault(vm *goja.Runtime, who, field, encField, defEnc string, want int) ([]byte, error) {
	v := o.get(field)
	if v == nil {
		return nil, fmt.Errorf("%s: %s is required", who, field)
	}
	var b []byte
	if _, isString := safeExportString(v); !isString {
		out, err := Bytes(vm, v)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", who, field, err)
		}
		b = out
	} else {
		enc := o.inputEncoding()
		if encField != "inputEncoding" {
			def := enc
			if defEnc != "" {
				def = defEnc
			}
			enc = o.optString(encField, def)
		}
		out, err := DecodeString(v.String(), enc)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", who, field, err)
		}
		b = out
	}
	if want > 0 && len(b) != want {
		if field == "seed" {
			// The doc's own sample passes a base64 seed with inputEncoding "utf8",
			// so point at the fix instead of just reporting the length.
			return nil, fmt.Errorf("%s: bad %s length: %d (want %d); for a base64 or hex seed pass seedEncoding", who, field, len(b), want)
		}
		return nil, fmt.Errorf("%s: bad %s length: %d (want %d)", who, field, len(b), want)
	}
	return b, nil
}

// safeExportString reports whether a JS value is a string.
func safeExportString(v goja.Value) (string, bool) {
	exported, err := safeExport(v)
	if err != nil {
		return "", false
	}
	s, ok := exported.(string)
	return s, ok
}
