package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func testVault(t *testing.T) *Vault {
	t.Helper()
	v, err := New(GenerateMasterKey())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

func TestNewRejectsKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := New(make([]byte, n)); err == nil {
			t.Errorf("New(%d-byte key) = nil error, want error", n)
		}
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	v := testVault(t)
	const plain = "super-secret-value"

	blob := v.Seal(plain)
	if bytes.Contains(blob, []byte(plain)) {
		t.Fatal("ciphertext contains the plaintext")
	}
	if len(blob) < 12+16 {
		t.Fatalf("blob length = %d, want at least nonce(12)+tag(16) overhead", len(blob))
	}
	got, err := v.Open(blob)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got != plain {
		t.Fatalf("Open = %q, want %q", got, plain)
	}
}

func TestSealUsesFreshNonce(t *testing.T) {
	v := testVault(t)
	a := v.Seal("same-plaintext")
	b := v.Seal("same-plaintext")
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same plaintext are identical (nonce reuse)")
	}
}

func TestOpenRejectsTamperedTruncatedAndWrongKey(t *testing.T) {
	v := testVault(t)
	blob := v.Seal("value")

	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := v.Open(tampered); err == nil {
		t.Error("Open accepted tampered ciphertext")
	}
	if _, err := v.Open(blob[:8]); err == nil {
		t.Error("Open accepted a too-short blob")
	}
	if _, err := testVault(t).Open(blob); err == nil {
		t.Error("a different master key decrypted the blob")
	}
}

func TestLookupCachesPerNameUntilInvalidated(t *testing.T) {
	v := testVault(t)
	calls := 0
	blobs := map[string][]byte{"api_key": v.Seal("v1")}
	fetch := func(name string) func() ([]byte, error) {
		return func() ([]byte, error) {
			calls++
			return blobs[name], nil
		}
	}

	got, ok := v.Lookup("api_key", fetch("api_key"))
	if !ok || got != "v1" {
		t.Fatalf("Lookup = (%q, %v), want (v1, true)", got, ok)
	}
	blobs["api_key"] = v.Seal("v2")
	if got, _ := v.Lookup("api_key", fetch("api_key")); got != "v1" {
		t.Fatalf("Lookup after overwrite = %q, want the cached v1", got)
	}
	if calls != 1 {
		t.Fatalf("fetch called %d times, want 1 (result should be cached)", calls)
	}

	// A write goes through Invalidate, which must drop the cached value.
	v.Invalidate()
	if got, ok := v.Lookup("api_key", fetch("api_key")); !ok || got != "v2" {
		t.Fatalf("Lookup after Invalidate = (%q, %v), want (v2, true)", got, ok)
	}
	if calls != 2 {
		t.Fatalf("fetch called %d times, want 2 after invalidation", calls)
	}
}

func TestLookupIsCachedPerName(t *testing.T) {
	v := testVault(t)
	blobs := map[string][]byte{"a": v.Seal("A"), "b": v.Seal("B")}
	for i := 0; i < 3; i++ {
		for name, want := range map[string]string{"a": "A", "b": "B"} {
			got, ok := v.Lookup(name, func() ([]byte, error) { return blobs[name], nil })
			if !ok || got != want {
				t.Fatalf("Lookup(%q) = (%q, %v), want (%q, true)", name, got, ok, want)
			}
		}
	}
}

func TestLookupReportsMissingAndUnreadable(t *testing.T) {
	v := testVault(t)
	if got, ok := v.Lookup("missing", func() ([]byte, error) { return nil, nil }); ok {
		t.Errorf("Lookup of a missing secret = (%q, true), want not ok", got)
	}
	if got, ok := v.Lookup("corrupt", func() ([]byte, error) { return []byte("not-ciphertext"), nil }); ok {
		t.Errorf("Lookup of an unreadable blob = (%q, true), want not ok", got)
	}
}

func TestDecodeMasterKey(t *testing.T) {
	key := GenerateMasterKey()
	for name, enc := range map[string]string{
		"hex":    hex.EncodeToString(key),
		"base64": base64.StdEncoding.EncodeToString(key),
	} {
		got, err := DecodeMasterKey(enc)
		if err != nil {
			t.Errorf("%s key: %v", name, err)
			continue
		}
		if !bytes.Equal(got, key) {
			t.Errorf("%s key: decoded value mismatch", name)
		}
	}
	for _, bad := range []string{"", "short", hex.EncodeToString(key[:16]), "not-a-key"} {
		if _, err := DecodeMasterKey(bad); err == nil {
			t.Errorf("DecodeMasterKey(%q) = nil error, want error", bad)
		}
	}
}

func TestLoadOrCreateMasterKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "master.key")

	k1, err := LoadOrCreateMasterKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateMasterKey: %v", err)
	}
	if len(k1) != 32 {
		t.Fatalf("generated key length = %d, want 32", len(k1))
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat master key: %v", err)
	}
	// os.WriteFile permissions are not enforced on Windows.
	if runtime.GOOS != "windows" {
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("master key file mode = %v, want 0600", perm)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read master key: %v", err)
	}
	if bytes.Contains(raw, k1) {
		t.Error("master key file contains raw key bytes; it should be encoded")
	}

	k2, err := LoadOrCreateMasterKey(path)
	if err != nil {
		t.Fatalf("reload master key: %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Error("reloaded master key differs from the generated one")
	}
}

func TestKeyFingerprint(t *testing.T) {
	k := GenerateMasterKey()
	fp := KeyFingerprint(k)
	if len(fp) != 8 {
		t.Fatalf("fingerprint length = %d, want 8 hex chars", len(fp))
	}
	if fp != KeyFingerprint(k) {
		t.Error("fingerprint is not stable for the same key")
	}
	if fp == KeyFingerprint(GenerateMasterKey()) {
		t.Error("different keys produced the same fingerprint")
	}
}
