package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

const (
	scryptN = 16384
	scryptR = 8
	scryptP = 1
	keyLen  = 64
	saltLen = 16
)

// HashPassword returns (hashHex, saltHex) for scrypt(N=16384, r=8, p=1, len=64).
func HashPassword(plain string) (string, string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", "", err
	}
	dk, err := scrypt.Key([]byte(plain), salt, scryptN, scryptR, scryptP, keyLen)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(dk), hex.EncodeToString(salt), nil
}

// VerifyPassword checks plain against stored hashHex/saltHex in constant time.
func VerifyPassword(plain, hashHex, saltHex string) bool {
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(hashHex)
	if err != nil || len(want) == 0 {
		return false
	}
	dk, err := scrypt.Key([]byte(plain), salt, scryptN, scryptR, scryptP, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(dk, want) == 1
}

// RandomPassword returns a cryptographically random human-readable password.
func RandomPassword(n int) (string, error) {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	if n < 8 {
		n = 16
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, c := range b {
		out[i] = alphabet[int(c)%len(alphabet)]
	}
	return string(out), nil
}

func EnsureRole(role string) (string, error) {
	if role == "admin" || role == "user" {
		return role, nil
	}
	return "", fmt.Errorf("invalid role %q", role)
}
