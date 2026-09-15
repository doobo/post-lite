package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

const SessionTTL = 24 * time.Hour

// NewToken returns (randomToken, storedHash). Only the sha256 hash of the
// token is persisted; the raw token lives in the browser cookie.
func NewToken() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	token := hex.EncodeToString(b)
	return token, TokenHash(token), nil
}

// TokenHash is the stable sha256 hex used as the session row id.
func TokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// AuditLine builds a compact audit log entry.
func AuditLine(actor, action, detail string) string {
	return fmt.Sprintf("%s | actor=%s | action=%s | %s", time.Now().UTC().Format(time.RFC3339), actor, action, detail)
}
