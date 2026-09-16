package script

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
)

// rfcSeedB64 is the base64 spelling of the RFC 8032 test-1 seed.
var rfcSeedB64 = base64.StdEncoding.EncodeToString(hexBytes(rfcSeed1))

const rfcData = "POST\n/orders\n1\nnonce"

func TestCryptoSignMatchesStandardLibrary(t *testing.T) {
	out := runJS(t, fmt.Sprintf(`
		const signature = pm.crypto.ed25519.sign({
			seed: %q,
			seedEncoding: 'base64',
			data: %q,
			inputEncoding: 'utf8',
			outputEncoding: 'base64',
		});
		const hexSig = pm.crypto.ed25519.sign({
			seed: %q,
			seedEncoding: 'hex',
			data: %q,
			outputEncoding: 'hex',
		});
		const rawSig = pm.crypto.ed25519.sign({seed: %q, seedEncoding: 'base64', data: %q, outputEncoding: 'bytes'});
		const nacl = pm.require('npm:tweetnacl@1.0.3');
		const kp = nacl.sign.keyPair.fromSeed(nacl.util.decodeBase64(%q));
		const compat = nacl.util.encodeBase64(nacl.sign.detached(nacl.util.decodeUTF8(%q), kp.secretKey));
		globalThis.out = {
			signature,
			hexSig,
			rawLen: rawSig.length,
			rawType: Object.prototype.toString.call(rawSig),
			compat,
		};
	`, rfcSeedB64, rfcData, rfcSeed1, rfcData, rfcSeedB64, rfcData, rfcSeedB64, rfcData))

	key := ed25519.NewKeyFromSeed(hexBytes(rfcSeed1))
	wantB64 := base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(rfcData)))
	if got := out["signature"]; got != wantB64 {
		t.Errorf("signature = %v, want %s", got, wantB64)
	}
	if got := out["hexSig"]; got != hex.EncodeToString(ed25519.Sign(key, []byte(rfcData))) {
		t.Errorf("hex signature = %v", got)
	}
	if out["rawLen"] != int64(64) || out["rawType"] != "[object Uint8Array]" {
		t.Errorf("raw output = %v / %v, want a 64-byte Uint8Array", out["rawLen"], out["rawType"])
	}
	if out["compat"] != out["signature"] {
		t.Errorf("native API (%v) and the tweetnacl layer (%v) disagree", out["signature"], out["compat"])
	}
}

func TestCryptoInputEncodingIsShared(t *testing.T) {
	// The doc's spelling: one inputEncoding for the seed and the data alike.
	out := runJS(t, fmt.Sprintf(`
		globalThis.out = {
			signature: pm.crypto.ed25519.sign({
				seed: %q,
				data: %q,
				inputEncoding: 'hex',
				outputEncoding: 'hex',
			}),
		};
	`, rfcSeed1, hex.EncodeToString([]byte("hello"))))

	want := hex.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(hexBytes(rfcSeed1)), []byte("hello")))
	if got := out["signature"]; got != want {
		t.Errorf("signature = %v, want %s", got, want)
	}
}

func TestCryptoVerifyAndKeyPair(t *testing.T) {
	out := runJS(t, fmt.Sprintf(`
		const kp = pm.crypto.ed25519.keyPairFromSeed({seed: %q, seedEncoding: 'base64'});
		const data = 'hello';
		const signature = pm.crypto.ed25519.sign({seed: %q, seedEncoding: 'base64', data});
		const rawKp = pm.crypto.ed25519.keyPairFromSeed({seed: %q, seedEncoding: 'base64', outputEncoding: 'bytes'});
		globalThis.out = {
			publicKey: kp.publicKey,
			secretKeyLen: kp.secretKey.length,
			byPublicKey: pm.crypto.ed25519.verify({publicKey: kp.publicKey, data, signature}),
			bySeed: pm.crypto.ed25519.verify({seed: %q, seedEncoding: 'base64', data, signature}),
			tamperedData: pm.crypto.ed25519.verify({publicKey: kp.publicKey, data: 'hellp', signature}),
			rawPublicKeyType: Object.prototype.toString.call(rawKp.publicKey),
			rawPublicKeyLen: rawKp.publicKey.length,
			rawSecretKeyLen: rawKp.secretKey.length,
		};
	`, rfcSeedB64, rfcSeedB64, rfcSeedB64, rfcSeedB64))

	if got := out["publicKey"]; got != base64.StdEncoding.EncodeToString(hexBytes(rfcPub1)) {
		t.Errorf("publicKey = %v, want the RFC 8032 test-1 public key", got)
	}
	if got := out["secretKeyLen"]; got != int64(88) { // 64 bytes in base64
		t.Errorf("secretKey (base64) length = %v, want 88", got)
	}
	if out["byPublicKey"] != true || out["bySeed"] != true {
		t.Errorf("verify = %v / %v, want true", out["byPublicKey"], out["bySeed"])
	}
	if out["tamperedData"] != false {
		t.Error("verify accepted tampered data")
	}
	if out["rawPublicKeyType"] != "[object Uint8Array]" {
		t.Errorf("raw public key type = %v", out["rawPublicKeyType"])
	}
	if out["rawPublicKeyLen"] != int64(32) || out["rawSecretKeyLen"] != int64(64) {
		t.Errorf("raw key sizes = %v / %v, want 32 / 64", out["rawPublicKeyLen"], out["rawSecretKeyLen"])
	}
}

func TestCryptoBadArguments(t *testing.T) {
	sig64 := "new Uint8Array(64)"
	cases := []struct{ name, body, want string }{
		{"noOptions", "pm.crypto.ed25519.sign()", "an options object is required"},
		{"stringOptions", "pm.crypto.ed25519.sign('nope')", "an options object is required"},
		{"noSeed", "pm.crypto.ed25519.sign({data: 'x'})", "seed is required"},
		{"noData", fmt.Sprintf("pm.crypto.ed25519.sign({seed: %q, seedEncoding: 'hex'})", rfcSeed1), "data is required"},
		{"base64SeedAsUtf8", fmt.Sprintf("pm.crypto.ed25519.sign({seed: %q, data: 'x'})", rfcSeedB64), "bad seed length: 44 (want 32); for a base64 or hex seed pass seedEncoding"},
		{"badSeedEncoding", "pm.crypto.ed25519.sign({seed: 'zz', seedEncoding: 'base64', data: 'x'})", "invalid base64 input"},
		{"badDataEncoding", fmt.Sprintf("pm.crypto.ed25519.sign({seed: %q, seedEncoding: 'hex', data: 'x', inputEncoding: 'nope'})", rfcSeed1), "unsupported input encoding"},
		{"badOutputEncoding", fmt.Sprintf("pm.crypto.ed25519.sign({seed: %q, seedEncoding: 'hex', data: 'x', outputEncoding: 'rot13'})", rfcSeed1), "unsupported output encoding"},
		{"badSignatureLength", "pm.crypto.ed25519.verify({publicKey: 'AAAA', data: 'x', signature: 'AA=='})", "bad signature length: 1 (want 64)"},
		{"noKeyInVerify", "pm.crypto.ed25519.verify({data: 'x', signature: " + sig64 + "})", "seed is required"},
		{"badPublicKeyLength", "pm.crypto.ed25519.verify({publicKey: 'AAAA', data: 'x', signature: " + sig64 + "})", "bad publicKey length: 3 (want 32)"},
		{"keyPairFromShortSeed", "pm.crypto.ed25519.keyPairFromSeed({seed: 'AAAA', seedEncoding: 'base64'})", "bad seed length: 3 (want 32)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectJSError(t, tc.body, tc.want)
		})
	}
}

// hexBytes decodes test-vector hex at init time.
func hexBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("script test: bad hex " + s)
	}
	return b
}
