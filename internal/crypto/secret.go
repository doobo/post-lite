package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const cacheTTL = 5 * time.Minute

// Vault encrypts secrets with AES-256-GCM using a 32-byte master key that
// lives outside the database. Decrypted values are cached in memory for a
// short TTL and invalidated on any write.
type Vault struct {
	aead  cipher.AEAD
	mu    sync.RWMutex
	cache map[string]cacheEntry
	gen   uint64
}

type cacheEntry struct {
	value   string
	expires time.Time
	gen     uint64
}

func New(key []byte) (*Vault, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Vault{aead: aead, cache: make(map[string]cacheEntry)}, nil
}

// Seal encrypts plaintext, storing nonce(12) || tag(16) || ciphertext.
func (v *Vault) Seal(plain string) []byte {
	nonce := make([]byte, 12)
	_, err := rand.Read(nonce)
	if err != nil {
		panic(err)
	}
	ct := v.aead.Seal(nil, nonce, []byte(plain), nil)
	out := make([]byte, 0, 12+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...) // ct already contains tag appended by GCM
	return out
}

// Open decrypts a blob produced by Seal.
func (v *Vault) Open(blob []byte) (string, error) {
	if len(blob) < 12 {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce := blob[:12]
	ct := blob[12:]
	plain, err := v.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// Invalidate clears the cache (call after writing/updating a secret).
func (v *Vault) Invalidate() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.gen++
	v.cache = make(map[string]cacheEntry)
}

// Lookup resolves a secret by name, using fetch to load its ciphertext.
// Returns the decrypted value and whether it was found. Results are cached
// for cacheTTL unless invalidated.
func (v *Vault) Lookup(name string, fetch func() ([]byte, error)) (string, bool) {
	v.mu.RLock()
	if e, ok := v.cache[name]; ok && e.gen == v.gen && time.Now().Before(e.expires) {
		v.mu.RUnlock()
		return e.value, true
	}
	v.mu.RUnlock()

	blob, err := fetch()
	if err != nil || blob == nil {
		return "", false
	}
	plain, err := v.Open(blob)
	if err != nil {
		return "", false
	}
	v.mu.Lock()
	v.cache[name] = cacheEntry{value: plain, expires: time.Now().Add(cacheTTL), gen: v.gen}
	v.mu.Unlock()
	return plain, true
}

// GenerateMasterKey returns 32 random bytes.
func GenerateMasterKey() []byte {
	k := make([]byte, 32)
	_, err := rand.Read(k)
	if err != nil {
		panic(err)
	}
	return k
}

// DecodeMasterKey parses a hex or base64 encoded 32-byte key.
func DecodeMasterKey(s string) ([]byte, error) {
	if k, err := hex.DecodeString(s); err == nil && len(k) == 32 {
		return k, nil
	}
	if k, err := base64.StdEncoding.DecodeString(s); err == nil && len(k) == 32 {
		return k, nil
	}
	return nil, fmt.Errorf("master key must be 32 bytes (hex or base64)")
}

// LoadOrCreateMasterKey loads the key from path, generating and persisting
// it (0600) when the file does not exist yet.
func LoadOrCreateMasterKey(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		if k, err := DecodeMasterKey(string(trimBytes(b))); err == nil {
			return k, nil
		}
	}
	k := GenerateMasterKey()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(base64.StdEncoding.EncodeToString(k)), 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	return k, nil
}

func trimBytes(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}

// KeyFingerprint returns a short log-safe identifier for a key.
func KeyFingerprint(key []byte) string {
	h := sha256.Sum256(key)
	return hex.EncodeToString(h[:4])
}
