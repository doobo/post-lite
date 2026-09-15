package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"
)

func newLoginCrypto(t *testing.T) *LoginCrypto {
	t.Helper()
	lc, err := NewLoginCrypto()
	if err != nil {
		t.Fatalf("NewLoginCrypto: %v", err)
	}
	return lc
}

// encryptFor is the browser half of the handshake, in the same wire format the
// UI produces.
func encryptFor(t *testing.T, pub *rsa.PublicKey, challenge, password string) string {
	t.Helper()
	plain, err := json.Marshal(loginPayload{Challenge: challenge, Password: password})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plain, nil)
	if err != nil {
		t.Fatalf("EncryptOAEP: %v", err)
	}
	return base64.StdEncoding.EncodeToString(ct)
}

func TestDecryptRoundTrip(t *testing.T) {
	lc := newLoginCrypto(t)
	ch, err := lc.NewChallenge()
	if err != nil {
		t.Fatalf("NewChallenge: %v", err)
	}

	got, err := lc.Decrypt(encryptFor(t, &lc.priv.PublicKey, ch, "s3cret-pw"))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != "s3cret-pw" {
		t.Errorf("password = %q, want %q", got, "s3cret-pw")
	}
	if lc.PendingChallenges() != 0 {
		t.Errorf("pending challenges = %d after a login, want 0", lc.PendingChallenges())
	}
}

// A challenge is consumed on use: the same ciphertext cannot log in twice.
func TestChallengeIsSingleUse(t *testing.T) {
	lc := newLoginCrypto(t)
	ch, err := lc.NewChallenge()
	if err != nil {
		t.Fatalf("NewChallenge: %v", err)
	}
	cipher := encryptFor(t, &lc.priv.PublicKey, ch, "pw")

	if _, err := lc.Decrypt(cipher); err != nil {
		t.Fatalf("first Decrypt: %v", err)
	}
	if _, err := lc.Decrypt(cipher); !errors.Is(err, ErrBadLoginPayload) {
		t.Errorf("replayed Decrypt err = %v, want ErrBadLoginPayload", err)
	}
}

func TestChallengeIsConsumedEvenWhenPasswordIsWrong(t *testing.T) {
	lc := newLoginCrypto(t)
	ch, err := lc.NewChallenge()
	if err != nil {
		t.Fatalf("NewChallenge: %v", err)
	}
	// The password check lives in the caller, so any decrypted payload burns the
	// challenge -- otherwise a wrong password could be retried against the same
	// challenge until it succeeds.
	if _, err := lc.Decrypt(encryptFor(t, &lc.priv.PublicKey, ch, "")); err != nil {
		t.Fatalf("Decrypt with an empty password: %v", err)
	}
	if _, err := lc.Decrypt(encryptFor(t, &lc.priv.PublicKey, ch, "pw")); !errors.Is(err, ErrBadLoginPayload) {
		t.Errorf("reuse of a spent challenge err = %v, want ErrBadLoginPayload", err)
	}
}

func TestExpiredChallengeIsRefused(t *testing.T) {
	lc := newLoginCrypto(t)
	ch, err := lc.NewChallenge()
	if err != nil {
		t.Fatalf("NewChallenge: %v", err)
	}
	cipher := encryptFor(t, &lc.priv.PublicKey, ch, "pw")

	lc.mu.Lock()
	lc.challenges[ch] = challenge{exp: time.Now().Add(-time.Second)}
	lc.mu.Unlock()

	if _, err := lc.Decrypt(cipher); !errors.Is(err, ErrBadLoginPayload) {
		t.Errorf("Decrypt of an expired challenge err = %v, want ErrBadLoginPayload", err)
	}
	if lc.PendingChallenges() != 0 {
		t.Errorf("pending challenges = %d, want 0 (expired entries are dropped)", lc.PendingChallenges())
	}
}

func TestDecryptRefusesUnknownOrForeignPayloads(t *testing.T) {
	lc := newLoginCrypto(t)
	other := newLoginCrypto(t) // a different key pair, as after a server restart
	ch, err := lc.NewChallenge()
	if err != nil {
		t.Fatalf("NewChallenge: %v", err)
	}

	cases := map[string]string{
		"empty":                 "",
		"not base64":            "not base64!!",
		"random 256 bytes":      base64.StdEncoding.EncodeToString(randomOf(t, 256)),
		"wrong key":             encryptFor(t, &other.priv.PublicKey, ch, "pw"),
		"unknown challenge":     encryptFor(t, &lc.priv.PublicKey, hex.EncodeToString(randomOf(t, 16)), "pw"),
		"empty challenge":       encryptFor(t, &lc.priv.PublicKey, "", "pw"),
		"unparseable plaintext": encryptRaw(t, &lc.priv.PublicKey, []byte("not json")),
	}
	for name, cipher := range cases {
		if _, err := lc.Decrypt(cipher); !errors.Is(err, ErrBadLoginPayload) {
			t.Errorf("%s: err = %v, want ErrBadLoginPayload", name, err)
		}
	}
}

func TestChallengeCountStaysBounded(t *testing.T) {
	lc := newLoginCrypto(t)
	first, err := lc.NewChallenge()
	if err != nil {
		t.Fatalf("NewChallenge: %v", err)
	}

	for i := 0; i < maxChallenges+16; i++ {
		if _, err := lc.NewChallenge(); err != nil {
			t.Fatalf("NewChallenge %d: %v", i, err)
		}
	}
	if got := lc.PendingChallenges(); got != maxChallenges {
		t.Errorf("pending challenges = %d, want the %d cap", got, maxChallenges)
	}

	// Flooding must not lock anyone out: the newest challenge still works and the
	// oldest one was evicted.
	newest, err := lc.NewChallenge()
	if err != nil {
		t.Fatalf("NewChallenge after the cap: %v", err)
	}
	if _, err := lc.Decrypt(encryptFor(t, &lc.priv.PublicKey, newest, "pw")); err != nil {
		t.Errorf("decrypt of the newest challenge: %v", err)
	}
	if _, err := lc.Decrypt(encryptFor(t, &lc.priv.PublicKey, first, "pw")); !errors.Is(err, ErrBadLoginPayload) {
		t.Errorf("evicted challenge err = %v, want ErrBadLoginPayload", err)
	}
}

// The browser gets the key twice: as an SPKI blob (WebCrypto importKey) and as
// n/e numbers (the loginenc.js fallback). Both must describe the same key.
func TestPublishedKeyMatchesThePrivateKey(t *testing.T) {
	lc := newLoginCrypto(t)

	der, err := base64.StdEncoding.DecodeString(lc.PublicKeyB64())
	if err != nil {
		t.Fatalf("public key is not base64: %v", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("public key is not SPKI DER: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want *rsa.PublicKey", pub)
	}

	modulus, ok := new(big.Int).SetString(lc.ModulusHex(), 16)
	if !ok {
		t.Fatalf("ModulusHex() = %q, not hex", lc.ModulusHex())
	}
	if modulus.Cmp(rsaPub.N) != 0 || modulus.Cmp(lc.priv.PublicKey.N) != 0 {
		t.Error("ModulusHex() does not match the SPKI blob's modulus")
	}
	if lc.Exponent() != rsaPub.E || lc.Exponent() != 65537 {
		t.Errorf("Exponent() = %d, want 65537", lc.Exponent())
	}
	if rsaPub.N.BitLen() != loginKeyBits {
		t.Errorf("modulus is %d bits, want %d", rsaPub.N.BitLen(), loginKeyBits)
	}
}

func randomOf(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}

func encryptRaw(t *testing.T, pub *rsa.PublicKey, plain []byte) string {
	t.Helper()
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plain, nil)
	if err != nil {
		t.Fatalf("EncryptOAEP: %v", err)
	}
	return base64.StdEncoding.EncodeToString(ct)
}
