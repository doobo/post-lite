package script

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"fmt"

	"github.com/dop251/goja"
)

// TweetNaclModule serves pm.require('npm:tweetnacl@1.0.3') from Go's
// crypto/ed25519, so a Postman script written against tweetnacl runs unchanged
// and no JS crypto library has to be downloaded, parsed or trusted.
//
// Implemented surface (everything else is absent on purpose, rather than
// silently faked):
//
//	nacl.sign(msg, secretKey)                       -> Uint8Array (sig||msg)
//	nacl.sign.detached(msg, secretKey)              -> Uint8Array(64)  (sign itself is callable, like tweetnacl)
//	nacl.sign.detached.verify(msg, sig, publicKey)  -> boolean
//	nacl.sign.open(signedMsg, publicKey)            -> Uint8Array | null
//	nacl.sign.keyPair()                             -> {publicKey, secretKey}
//	nacl.sign.keyPair.fromSeed(seed)                -> {publicKey, secretKey}
//	nacl.sign.keyPair.fromSecretKey(sk)             -> {publicKey, secretKey}
//	nacl.randomBytes(n)                             -> Uint8Array(n)
//	nacl.hash(msg)                                  -> Uint8Array(64)  (SHA-512)
//	nacl.util.{decode,encode}{UTF8,Base64,Hex}
//
// secretKey is the 64-byte tweetnacl form (32-byte seed followed by the public
// key), which is exactly what crypto/ed25519.PrivateKey is.
type TweetNaclModule struct{}

// tweetNaclID is the canonical ID the doc's compatibility layer maps from.
const tweetNaclID = "npm:tweetnacl@1.0.3"

// ID implements BuiltinModule.
func (TweetNaclModule) ID() string { return tweetNaclID }

// Register implements BuiltinModule.
func (TweetNaclModule) Register(vm *goja.Runtime) goja.Value {
	nacl := vm.NewObject()
	nacl.Set("sign", naclSign(vm))
	nacl.Set("randomBytes", naclRandomBytes(vm))
	nacl.Set("hash", naclHash(vm))
	nacl.Set("util", naclUtil(vm))
	return nacl
}

// naclSign builds nacl.sign. In tweetnacl `sign` is a function that also
// carries detached / keyPair / open, so scripts can call nacl.sign(msg, sk)
// directly; a plain object would break those scripts with "not a function".
func naclSign(vm *goja.Runtime) *goja.Object {
	// nacl.sign(msg, sk): the signed message, signature first.
	sign := vm.ToValue(func(call goja.FunctionCall) goja.Value {
		msg, err := Bytes(vm, call.Argument(0))
		if err != nil {
			throwType(vm, "nacl.sign.sign: %v", err)
		}
		key, err := naclSecretKey(vm, "nacl.sign.sign", call.Argument(1))
		if err != nil {
			throwType(vm, "%v", err)
		}
		signed := make([]byte, 0, ed25519.SignatureSize+len(msg))
		signed = append(signed, ed25519.Sign(key, msg)...)
		signed = append(signed, msg...)
		return NewBytes(vm, signed)
	}).(*goja.Object)

	// nacl.sign.detached(msg, sk) plus its .verify sibling.
	detached := vm.ToValue(func(call goja.FunctionCall) goja.Value {
		msg, err := Bytes(vm, call.Argument(0))
		if err != nil {
			throwType(vm, "nacl.sign.detached: %v", err)
		}
		key, err := naclSecretKey(vm, "nacl.sign.detached", call.Argument(1))
		if err != nil {
			throwType(vm, "%v", err)
		}
		return NewBytes(vm, ed25519.Sign(key, msg))
	}).(*goja.Object)

	detached.Set("verify", func(call goja.FunctionCall) goja.Value {
		msg, err := Bytes(vm, call.Argument(0))
		if err != nil {
			throwType(vm, "nacl.sign.detached.verify: %v", err)
		}
		sig, err := Bytes(vm, call.Argument(1))
		if err != nil {
			throwType(vm, "nacl.sign.detached.verify: %v", err)
		}
		if len(sig) != ed25519.SignatureSize {
			throwType(vm, "nacl.sign.detached.verify: bad signature length: %d (want %d)", len(sig), ed25519.SignatureSize)
		}
		pub, err := naclPublicKey(vm, "nacl.sign.detached.verify", call.Argument(2))
		if err != nil {
			throwType(vm, "%v", err)
		}
		return vm.ToValue(ed25519.Verify(pub, msg, sig))
	})
	sign.Set("detached", detached)

	// nacl.sign.open(signedMsg, pk): the message, or null if the signature
	// does not check out (same contract as tweetnacl).
	sign.Set("open", func(call goja.FunctionCall) goja.Value {
		signed, err := Bytes(vm, call.Argument(0))
		if err != nil {
			throwType(vm, "nacl.sign.open: %v", err)
		}
		pub, err := naclPublicKey(vm, "nacl.sign.open", call.Argument(1))
		if err != nil {
			throwType(vm, "%v", err)
		}
		if len(signed) < ed25519.SignatureSize {
			throwType(vm, "nacl.sign.open: bad signed message length: %d", len(signed))
		}
		msg := signed[ed25519.SignatureSize:]
		if !ed25519.Verify(pub, msg, signed[:ed25519.SignatureSize]) {
			return goja.Null()
		}
		return NewBytes(vm, msg)
	})

	sign.Set("keyPair", naclKeyPair(vm))
	return sign
}

// naclKeyPair mirrors tweetnacl, where keyPair is itself a function
// (generate a fresh pair) carrying fromSeed / fromSecretKey.
func naclKeyPair(vm *goja.Runtime) *goja.Object {
	generate := vm.ToValue(func(call goja.FunctionCall) goja.Value {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			throwType(vm, "nacl.sign.keyPair: %v", err)
		}
		return naclKeyPairObject(vm, pub, priv)
	}).(*goja.Object)

	generate.Set("fromSeed", func(call goja.FunctionCall) goja.Value {
		seed, err := Bytes(vm, call.Argument(0))
		if err != nil {
			throwType(vm, "nacl.sign.keyPair.fromSeed: %v", err)
		}
		if len(seed) != ed25519.SeedSize {
			throwType(vm, "nacl.sign.keyPair.fromSeed: bad seed length: %d (want %d)", len(seed), ed25519.SeedSize)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		return naclKeyPairObject(vm, priv.Public().(ed25519.PublicKey), priv)
	})

	generate.Set("fromSecretKey", func(call goja.FunctionCall) goja.Value {
		priv, err := naclSecretKey(vm, "nacl.sign.keyPair.fromSecretKey", call.Argument(0))
		if err != nil {
			throwType(vm, "%v", err)
		}
		return naclKeyPairObject(vm, priv.Public().(ed25519.PublicKey), priv)
	})

	return generate
}

func naclKeyPairObject(vm *goja.Runtime, pub ed25519.PublicKey, priv ed25519.PrivateKey) *goja.Object {
	kp := vm.NewObject()
	kp.Set("publicKey", NewBytes(vm, pub))
	kp.Set("secretKey", NewBytes(vm, priv))
	return kp
}

func naclRandomBytes(vm *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		n := call.Argument(0).ToInteger()
		if n < 0 || n > maxBytes {
			throwType(vm, "nacl.randomBytes: bad length: %d", n)
		}
		out := make([]byte, n)
		if _, err := rand.Read(out); err != nil {
			throwType(vm, "nacl.randomBytes: %v", err)
		}
		return NewBytes(vm, out)
	}
}

func naclHash(vm *goja.Runtime) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		msg, err := Bytes(vm, call.Argument(0))
		if err != nil {
			throwType(vm, "nacl.hash: %v", err)
		}
		sum := sha512.Sum512(msg)
		return NewBytes(vm, sum[:])
	}
}

// naclUtil provides tweetnacl's encoding helpers, which is what most old
// scripts wrap in their own base64ToUint8Array / utf8ToUint8Array functions.
func naclUtil(vm *goja.Runtime) *goja.Object {
	util := vm.NewObject()
	util.Set("decodeUTF8", func(s string) goja.Value { return NewBytes(vm, []byte(s)) })
	util.Set("encodeUTF8", func(call goja.FunctionCall) goja.Value {
		b, err := Bytes(vm, call.Argument(0))
		if err != nil {
			throwType(vm, "nacl.util.encodeUTF8: %v", err)
		}
		return vm.ToValue(string(b))
	})
	util.Set("decodeBase64", func(call goja.FunctionCall) goja.Value {
		b, err := DecodeString(call.Argument(0).String(), "base64")
		if err != nil {
			throwType(vm, "nacl.util.decodeBase64: %v", err)
		}
		return NewBytes(vm, b)
	})
	util.Set("encodeBase64", func(call goja.FunctionCall) goja.Value {
		b, err := Bytes(vm, call.Argument(0))
		if err != nil {
			throwType(vm, "nacl.util.encodeBase64: %v", err)
		}
		s, err := EncodeBytes(b, "base64")
		if err != nil {
			throwType(vm, "nacl.util.encodeBase64: %v", err)
		}
		return vm.ToValue(s)
	})
	util.Set("decodeHex", func(call goja.FunctionCall) goja.Value {
		b, err := DecodeString(call.Argument(0).String(), "hex")
		if err != nil {
			throwType(vm, "nacl.util.decodeHex: %v", err)
		}
		return NewBytes(vm, b)
	})
	util.Set("encodeHex", func(call goja.FunctionCall) goja.Value {
		b, err := Bytes(vm, call.Argument(0))
		if err != nil {
			throwType(vm, "nacl.util.encodeHex: %v", err)
		}
		return vm.ToValue(fmt.Sprintf("%x", b))
	})
	return util
}

// naclSecretKey reads a tweetnacl secret key (seed || publicKey, 64 bytes).
func naclSecretKey(vm *goja.Runtime, who string, v goja.Value) (ed25519.PrivateKey, error) {
	b, err := Bytes(vm, v)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", who, err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s: bad secret key length: %d (want %d)", who, len(b), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(b), nil
}

// naclPublicKey accepts a 32-byte public key, and also a 64-byte secret key —
// tweetnacl callers often pass keyPair.secretKey by mistake, and the public half
// is right there, so honouring it keeps those scripts working.
func naclPublicKey(vm *goja.Runtime, who string, v goja.Value) (ed25519.PublicKey, error) {
	b, err := Bytes(vm, v)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", who, err)
	}
	switch len(b) {
	case ed25519.PublicKeySize:
		return ed25519.PublicKey(b), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(b).Public().(ed25519.PublicKey), nil
	default:
		return nil, fmt.Errorf("%s: bad public key length: %d (want %d)", who, len(b), ed25519.PublicKeySize)
	}
}
