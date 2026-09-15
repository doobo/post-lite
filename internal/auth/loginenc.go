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
	"sync"
	"time"
)

// LoginCrypto is the server half of the login handshake: the browser fetches an
// ephemeral RSA public key plus a single-use challenge, encrypts
// {"c": challenge, "p": password} with RSA-OAEP/SHA-256, and this type decrypts
// it again. The challenge is consumed on use, so a captured request cannot be
// replayed.
//
// The browser encrypts with WebCrypto when it has it (a secure context: HTTPS or
// localhost). A plain-HTTP intranet deployment is *not* a secure context, so
// crypto.subtle does not exist there and the UI falls back to the pure-JS
// implementation in internal/web/static/loginenc.js — which is why the key
// endpoint also publishes the raw modulus and exponent next to the SPKI blob.
//
// This is defence in depth for the password itself, not a replacement for TLS:
// it keeps the clear-text password out of request bodies that corporate proxies,
// access logs and browser devtools would otherwise record, and it also covers
// `-plain` development mode. It cannot protect against an attacker who can
// tamper with the key endpoint (an active MITM) — that is what TLS is for.
const (
	// ChallengeTTL is how long an issued challenge stays valid.
	ChallengeTTL = 2 * time.Minute

	loginKeyBits  = 2048
	maxChallenges = 4096
)

// ErrBadLoginPayload means the ciphertext could not be decrypted, the payload
// did not parse, or the challenge was unknown, expired or already used. The
// reason is deliberately not distinguished: the caller only ever shows one
// message and an attacker learns nothing extra.
var ErrBadLoginPayload = errors.New("bad login payload")

// loginPayload is the JSON envelope carried inside the ciphertext.
type loginPayload struct {
	Challenge string `json:"c"`
	Password  string `json:"p"`
}

// challenge is one outstanding nonce. seq orders issues so that a full map can
// evict the oldest entry deterministically (wall-clock expiries can tie on
// platforms with a coarse clock, which would make eviction order random).
type challenge struct {
	exp time.Time
	seq uint64
}

// LoginCrypto holds one ephemeral key pair for the lifetime of the process:
// restarting the server invalidates outstanding login keys, which is fine
// because the browser fetches one immediately before each sign-in.
type LoginCrypto struct {
	priv   *rsa.PrivateKey
	pubB64 string

	mu         sync.Mutex
	challenges map[string]challenge
	nextSeq    uint64
}

// NewLoginCrypto generates the ephemeral key pair.
func NewLoginCrypto() (*LoginCrypto, error) {
	priv, err := rsa.GenerateKey(rand.Reader, loginKeyBits)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return &LoginCrypto{
		priv:       priv,
		pubB64:     base64.StdEncoding.EncodeToString(der),
		challenges: make(map[string]challenge),
	}, nil
}

// PublicKeyB64 returns the SPKI (DER) public key, base64 encoded — the exact
// bytes WebCrypto's importKey("spki", ...) expects.
func (c *LoginCrypto) PublicKeyB64() string { return c.pubB64 }

// ModulusHex returns the RSA modulus as minimal big-endian hex. It is published
// so the pure-JS fallback can encrypt without a DER parser; the SPKI blob stays
// the canonical form for WebCrypto.
func (c *LoginCrypto) ModulusHex() string {
	return hex.EncodeToString(c.priv.PublicKey.N.Bytes())
}

// Exponent is the public exponent (always 65537 for the keys generated here).
func (c *LoginCrypto) Exponent() int { return c.priv.PublicKey.E }

// NewChallenge issues a single-use nonce that must come back inside the
// ciphertext. Expired nonces are dropped opportunistically, and a hard cap keeps
// an unauthenticated endpoint from growing the map without bound.
func (c *LoginCrypto) NewChallenge() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	ch := hex.EncodeToString(b)

	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, c0 := range c.challenges {
		if now.After(c0.exp) {
			delete(c.challenges, k)
		}
	}
	if len(c.challenges) >= maxChallenges {
		// An unauthenticated endpoint must not be able to make everyone else
		// unable to log in, so a full map evicts the oldest challenge instead of
		// refusing the new one. A flood then only ages out its own entries.
		oldest, oldestSeq := "", uint64(0)
		for k, c0 := range c.challenges {
			if oldest == "" || c0.seq < oldestSeq {
				oldest, oldestSeq = k, c0.seq
			}
		}
		delete(c.challenges, oldest)
	}
	c.nextSeq++
	c.challenges[ch] = challenge{exp: now.Add(ChallengeTTL), seq: c.nextSeq}
	return ch, nil
}

// Decrypt unwraps a base64 RSA-OAEP ciphertext and returns the password, after
// checking that its embedded challenge is one this server issued, unexpired and
// unused. The challenge is consumed even when the password turns out to be
// wrong, so a failed attempt cannot be replayed either.
func (c *LoginCrypto) Decrypt(cipherB64 string) (string, error) {
	ct, err := base64.StdEncoding.DecodeString(cipherB64)
	if err != nil {
		return "", ErrBadLoginPayload
	}
	plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, c.priv, ct, nil)
	if err != nil {
		return "", ErrBadLoginPayload
	}
	var p loginPayload
	if err := json.Unmarshal(plain, &p); err != nil {
		return "", ErrBadLoginPayload
	}
	if !c.consume(p.Challenge) {
		return "", ErrBadLoginPayload
	}
	return p.Password, nil
}

// consume reports whether the challenge was outstanding, removing it either way.
func (c *LoginCrypto) consume(ch string) bool {
	if ch == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c0, ok := c.challenges[ch]
	if !ok {
		return false
	}
	delete(c.challenges, ch)
	return !time.Now().After(c0.exp)
}

// PendingChallenges reports how many challenges are outstanding (used by tests).
func (c *LoginCrypto) PendingChallenges() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.challenges)
}
