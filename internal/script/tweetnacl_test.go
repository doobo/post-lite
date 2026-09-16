package script

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"testing"
)

// RFC 8032 test vectors: the ground truth for "this really is Ed25519", not just
// a self-consistent round trip.
const (
	rfcSeed1 = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	rfcPub1  = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	rfcMsg1  = ""
	rfcSig1  = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"

	rfcSeed2 = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
	rfcPub2  = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
	rfcMsg2  = "72"
	rfcSig2  = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
)

// naclScript exercises the compatibility layer the way an old Postman script
// does: hex in, hex out, no helper functions of its own.
func naclScript(body string) string {
	return "const nacl = pm.require('npm:tweetnacl@1.0.3');\n" + body
}

func TestTweetNaclRFC8032Vectors(t *testing.T) {
	vectors := []struct{ name, seed, pub, msg, sig string }{
		{"empty-message", rfcSeed1, rfcPub1, rfcMsg1, rfcSig1},
		{"single-byte", rfcSeed2, rfcPub2, rfcMsg2, rfcSig2},
	}
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			out := runJS(t, naclScript(fmt.Sprintf(`
				const kp = nacl.sign.keyPair.fromSeed(nacl.util.decodeHex(%q));
				const msg = nacl.util.decodeHex(%q);
				const sig = nacl.sign.detached(msg, kp.secretKey);
				globalThis.out = {
					publicKey: nacl.util.encodeHex(kp.publicKey),
					secretKeyLen: kp.secretKey.length,
					publicKeyLen: kp.publicKey.length,
					secretKeyStartsWithSeed: nacl.util.encodeHex(kp.secretKey).startsWith(%q),
					secretKeyPublicHalf: nacl.util.encodeHex(kp.secretKey).slice(64),
					signature: nacl.util.encodeHex(sig),
					signatureLen: sig.length,
					signatureType: Object.prototype.toString.call(sig),
					verify: nacl.sign.detached.verify(msg, sig, kp.publicKey),
				};
			`, v.seed, v.msg, v.seed)))

			if got := out["publicKey"]; got != v.pub {
				t.Errorf("publicKey = %v, want %s", got, v.pub)
			}
			if got := out["signature"]; got != v.sig {
				t.Errorf("signature = %v, want %s", got, v.sig)
			}
			if got := out["secretKeyPublicHalf"]; got != v.pub {
				t.Errorf("secretKey public half = %v, want %s", got, v.pub)
			}
			for field, want := range map[string]any{
				"signatureLen":            int64(64),
				"signatureType":           "[object Uint8Array]",
				"secretKeyLen":            int64(64),
				"publicKeyLen":            int64(32),
				"secretKeyStartsWithSeed": true,
				"verify":                  true,
			} {
				if got := out[field]; got != want {
					t.Errorf("%s = %v (%T), want %v", field, got, got, want)
				}
			}
		})
	}
}

func TestTweetNaclVerifyRejectsTampering(t *testing.T) {
	out := runJS(t, naclScript(fmt.Sprintf(`
		const kp = nacl.sign.keyPair.fromSeed(nacl.util.decodeHex(%q));
		const msg = nacl.util.decodeHex(%q);
		const sig = nacl.sign.detached(msg, kp.secretKey);
		const badSig = new Uint8Array(sig); badSig[0] ^= 0x01;
		const badMsg = new Uint8Array(msg.length + 1); badMsg[msg.length] = 0x01;
		const other = nacl.sign.keyPair.fromSeed(nacl.util.decodeHex(%q));
		globalThis.out = {
			tamperedSig: nacl.sign.detached.verify(msg, badSig, kp.publicKey),
			tamperedMsg: nacl.sign.detached.verify(badMsg, sig, kp.publicKey),
			wrongKey: nacl.sign.detached.verify(msg, sig, other.publicKey),
			good: nacl.sign.detached.verify(msg, sig, kp.publicKey),
			secretKeyAsPublicKey: nacl.sign.detached.verify(msg, sig, kp.secretKey),
		};
	`, rfcSeed2, rfcMsg2, rfcSeed1)))

	for _, k := range []string{"tamperedSig", "tamperedMsg", "wrongKey"} {
		if out[k] != false {
			t.Errorf("%s = %v, want false", k, out[k])
		}
	}
	if out["good"] != true {
		t.Error("valid signature did not verify")
	}
	if out["secretKeyAsPublicKey"] != true {
		t.Error("passing a secretKey where a publicKey is expected should work")
	}
}

func TestTweetNaclSignOpenRoundTrip(t *testing.T) {
	const msgHex = "deadbeef"
	out := runJS(t, naclScript(fmt.Sprintf(`
		const kp = nacl.sign.keyPair.fromSeed(nacl.util.decodeHex(%q));
		const msg = nacl.util.decodeHex(%q);
		const signed = nacl.sign(msg, kp.secretKey);
		const opened = nacl.sign.open(signed, kp.publicKey);
		const bad = new Uint8Array(signed); bad[0] ^= 0x01;
		globalThis.out = {
			signedHex: nacl.util.encodeHex(signed),
			signedLen: signed.length,
			openedHex: nacl.util.encodeHex(opened),
			openedIsNull: nacl.sign.open(bad, kp.publicKey) === null,
		};
	`, rfcSeed1, msgHex)))

	// Expected signed message, straight from the standard library: signature
	// first, then the message (tweetnacl's sig||msg layout).
	msg := mustHex(t, msgHex)
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(mustHex(t, rfcSeed1)), msg)
	expected := hex.EncodeToString(append(append([]byte{}, sig...), msg...))

	if got := out["signedHex"]; got != expected {
		t.Errorf("sign() = %v, want %s", got, expected)
	}
	if got := out["signedLen"]; got != int64(64+len(msgHex)/2) {
		t.Errorf("signed length = %v, want %d", got, 64+len(msgHex)/2)
	}
	if got := out["openedHex"]; got != msgHex {
		t.Errorf("open() = %v, want %s", got, msgHex)
	}
	if out["openedIsNull"] != true {
		t.Error("open() accepted a tampered signed message")
	}
}

func TestTweetNaclKeyPairGenerate(t *testing.T) {
	out := runJS(t, naclScript(`
		const a = nacl.sign.keyPair();
		const b = nacl.sign.keyPair();
		const msg = nacl.util.decodeUTF8('ping');
		const sig = nacl.sign.detached(msg, a.secretKey);
		globalThis.out = {
			aPubLen: a.publicKey.length,
			aSecLen: a.secretKey.length,
			sameKey: nacl.util.encodeHex(a.publicKey) === nacl.util.encodeHex(b.publicKey),
			verify: nacl.sign.detached.verify(msg, sig, a.publicKey),
			fromSecretKey: nacl.util.encodeHex(nacl.sign.keyPair.fromSecretKey(a.secretKey).publicKey) === nacl.util.encodeHex(a.publicKey),
		};
	`))

	if out["aPubLen"] != int64(32) || out["aSecLen"] != int64(64) {
		t.Errorf("unexpected key sizes: %v / %v", out["aPubLen"], out["aSecLen"])
	}
	if out["sameKey"] != false {
		t.Error("two generated key pairs are identical")
	}
	if out["verify"] != true {
		t.Error("signature from a generated key pair did not verify")
	}
	if out["fromSecretKey"] != true {
		t.Error("fromSecretKey did not recover the public key")
	}
}

func TestTweetNaclAcceptsStringsAndArrays(t *testing.T) {
	out := runJS(t, naclScript(fmt.Sprintf(`
		const kp = nacl.sign.keyPair.fromSeed(nacl.util.decodeHex(%q));
		const kpFromArray = nacl.sign.keyPair.fromSeed([...nacl.util.decodeHex(%q)]);
		const fromString = nacl.sign.detached('hello', kp.secretKey);
		const fromBytes = nacl.sign.detached(nacl.util.decodeUTF8('hello'), kp.secretKey);
		const fromArray = nacl.sign.detached(new Uint8Array([104, 101, 108, 108, 111]), kp.secretKey);
		const fromNumberArray = nacl.sign.detached([104, 101, 108, 108, 111], kp.secretKey);
		globalThis.out = {
			sameKeyPair: nacl.util.encodeHex(kpFromArray.publicKey) === nacl.util.encodeHex(kp.publicKey),
			sameStringAndBytes: nacl.util.encodeHex(fromString) === nacl.util.encodeHex(fromBytes),
			sameArrayAndBytes: nacl.util.encodeHex(fromArray) === nacl.util.encodeHex(fromBytes),
			sameNumberArrayAndBytes: nacl.util.encodeHex(fromNumberArray) === nacl.util.encodeHex(fromBytes),
		};
	`, rfcSeed1, rfcSeed1)))

	for k, want := range map[string]any{
		"sameKeyPair":             true,
		"sameStringAndBytes":      true,
		"sameArrayAndBytes":       true,
		"sameNumberArrayAndBytes": true,
	} {
		if out[k] != want {
			t.Errorf("%s = %v, want %v", k, out[k], want)
		}
	}
}

func TestTweetNaclHashAndRandomBytes(t *testing.T) {
	out := runJS(t, naclScript(`
		const h = nacl.hash(nacl.util.decodeUTF8('abc'));
		const r1 = nacl.randomBytes(8);
		const r2 = nacl.randomBytes(8);
		globalThis.out = {
			hashHex: nacl.util.encodeHex(h),
			hashLen: h.length,
			r1: nacl.util.encodeHex(r1),
			r2: nacl.util.encodeHex(r2),
			rLen: r1.length,
			rType: Object.prototype.toString.call(r1),
			zeroLen: nacl.randomBytes(0).length,
		};
	`))

	want := fmt.Sprintf("%x", sha512.Sum512([]byte("abc")))
	if out["hashHex"] != want {
		t.Errorf("hash = %v, want %s", out["hashHex"], want)
	}
	for field, want := range map[string]any{
		"hashLen": int64(64),
		"rLen":    int64(8),
		"zeroLen": int64(0),
		"rType":   "[object Uint8Array]",
	} {
		if got := out[field]; got != want {
			t.Errorf("%s = %v, want %v", field, got, want)
		}
	}
	if out["r1"] == out["r2"] {
		t.Error("randomBytes returned the same bytes twice")
	}
}

func TestTweetNaclUtilBase64(t *testing.T) {
	out := runJS(t, naclScript(`
		globalThis.out = {
			raw: nacl.util.encodeUTF8(nacl.util.decodeBase64('aGVsbG8=')),
			b64: nacl.util.encodeBase64(nacl.util.decodeUTF8('hello')),
			hex: nacl.util.encodeHex(nacl.util.decodeUTF8('hi')),
			back: nacl.util.encodeHex(nacl.util.decodeHex('6869')),
			utf8: nacl.util.encodeUTF8(nacl.util.decodeUTF8('汉字')),
		};
	`))
	for k, want := range map[string]any{
		"raw": "hello", "b64": "aGVsbG8=", "hex": "6869", "back": "6869", "utf8": "汉字",
	} {
		if out[k] != want {
			t.Errorf("%s = %v, want %v", k, out[k], want)
		}
	}
}

func TestTweetNaclBadArguments(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"shortSeed", "nacl.sign.keyPair.fromSeed(new Uint8Array(16))", "bad seed length: 16 (want 32)"},
		{"shortSecretKey", "nacl.sign.detached('m', new Uint8Array(32))", "bad secret key length: 32 (want 64)"},
		{"missingMessage", "nacl.sign.detached(null, new Uint8Array(64))", "expected a byte sequence"},
		{"badSignatureSize", "nacl.sign.detached.verify('m', new Uint8Array(3), new Uint8Array(32))", "bad signature length: 3 (want 64)"},
		{"badPublicKey", "nacl.sign.detached.verify('m', new Uint8Array(64), new Uint8Array(31))", "bad public key length: 31 (want 32)"},
		{"badRandomLength", "nacl.randomBytes(-1)", "bad length: -1"},
		{"badBase64", "nacl.util.decodeBase64('!!!')", "invalid base64 input"},
		{"emptySignedMessage", "nacl.sign.open(new Uint8Array(3), new Uint8Array(32))", "bad signed message length: 3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectJSError(t, naclScript(tc.body), tc.want)
		})
	}
}

// TestTweetNaclSurface documents which members exist: anything post-lite does
// not implement (nacl.box, nacl.secretbox, ...) stays undefined rather than
// being faked with a wrong implementation.
func TestTweetNaclSurface(t *testing.T) {
	out := runJS(t, naclScript(`
		globalThis.out = {
			box: typeof nacl.box,
			signIsCallable: typeof nacl.sign,
			signOpen: typeof nacl.sign.open,
			detached: typeof nacl.sign.detached,
			detachedVerify: typeof nacl.sign.detached.verify,
			keyPairFromSeed: typeof nacl.sign.keyPair.fromSeed,
		};
	`))
	if out["box"] != "undefined" {
		t.Errorf("nacl.box = %v, want undefined (not implemented)", out["box"])
	}
	// nacl.sign is a function carrying its own methods, exactly like tweetnacl.
	for _, field := range []string{"signIsCallable", "signOpen", "detached", "detachedVerify", "keyPairFromSeed"} {
		if out[field] != "function" {
			t.Errorf("%s = %v, want function", field, out[field])
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}
