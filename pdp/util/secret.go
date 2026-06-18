package util

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

const secretHashPrefix = "sha256:"

// GenerateSecretToken returns a URL-safe secret token with the given prefix.
func GenerateSecretToken(prefix string, entropyBytes int) (string, error) {
	prefix = strings.Trim(strings.TrimSpace(prefix), "_")
	if prefix == "" {
		prefix = "secret"
	}
	if entropyBytes < 32 {
		entropyBytes = 32
	}
	raw := make([]byte, entropyBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate secret token: %w", err)
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

// HashSecretToken returns a one-way hash suitable for persistent storage.
func HashSecretToken(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	if strings.HasPrefix(token, secretHashPrefix) {
		return token
	}
	sum := sha256.Sum256([]byte(token))
	return secretHashPrefix + hex.EncodeToString(sum[:])
}

// VerifySecretToken compares a presented token with a stored hash.
func VerifySecretToken(stored, presented string) bool {
	stored = strings.TrimSpace(stored)
	presented = strings.TrimSpace(presented)
	if stored == "" || presented == "" || !strings.HasPrefix(stored, secretHashPrefix) {
		return false
	}
	expected := HashSecretToken(presented)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(stored)) == 1
}
