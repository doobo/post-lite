package auth

import (
	"strings"
	"testing"
)

func TestRateLimiterLocksAfterFiveFailures(t *testing.T) {
	rl := NewRateLimiter()
	const ip = "10.0.0.9"

	if rl.IsLocked(ip) {
		t.Fatal("a fresh limiter reports the IP as locked")
	}
	for i := 0; i < maxFails-1; i++ {
		rl.NoteFail(ip)
	}
	if rl.IsLocked(ip) {
		t.Fatalf("locked after only %d failures", maxFails-1)
	}
	rl.NoteFail(ip)
	if !rl.IsLocked(ip) {
		t.Fatalf("not locked after %d failures", maxFails)
	}
	rl.Reset(ip)
	if rl.IsLocked(ip) {
		t.Fatal("still locked after a successful login reset")
	}
}

func TestRateLimiterIsPerIP(t *testing.T) {
	rl := NewRateLimiter()
	for i := 0; i < maxFails; i++ {
		rl.NoteFail("10.0.0.1")
	}
	if !rl.IsLocked("10.0.0.1") {
		t.Fatal("10.0.0.1 should be locked")
	}
	if rl.IsLocked("10.0.0.2") {
		t.Fatal("the lock leaked to another IP")
	}
}

func TestNewTokenStoresOnlyTheHash(t *testing.T) {
	token, hash, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if len(token) != 64 {
		t.Errorf("token length = %d, want 64 hex chars", len(token))
	}
	if token == hash {
		t.Fatal("the stored session id equals the raw token")
	}
	if hash != TokenHash(token) {
		t.Error("TokenHash does not match the stored session id")
	}
	if len(hash) != 64 {
		t.Errorf("session id length = %d, want 64 hex chars", len(hash))
	}

	token2, hash2, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if token2 == token || hash2 == hash {
		t.Error("tokens are not unique between calls")
	}
}

func TestHashPasswordRoundTrip(t *testing.T) {
	const password = "correct horse battery staple"
	if _, _, err := HashPassword(password); err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	hash, salt, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "" || salt == "" {
		t.Fatal("HashPassword returned an empty hash or salt")
	}
	if strings.Contains(hash, password) {
		t.Fatal("the stored hash contains the plaintext password")
	}
	if !VerifyPassword(password, hash, salt) {
		t.Error("the correct password was rejected")
	}
	if VerifyPassword("wrong password", hash, salt) {
		t.Error("a wrong password was accepted")
	}
	// Malformed stored values must fail closed, never panic or succeed.
	if VerifyPassword(password, hash, "not-hex") {
		t.Error("a non-hex salt was accepted")
	}
	if VerifyPassword(password, "", salt) {
		t.Error("an empty hash was accepted")
	}

	hash2, salt2, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash2 == hash || salt2 == salt {
		t.Error("the same password produced an identical hash/salt (salt is not unique)")
	}
}

func TestAuditLineNamesTheActor(t *testing.T) {
	line := AuditLine("admin", "secret.create", "name=api_key")
	for _, want := range []string{"actor=admin", "action=secret.create", "name=api_key"} {
		if !strings.Contains(line, want) {
			t.Errorf("audit line %q is missing %q", line, want)
		}
	}
}
