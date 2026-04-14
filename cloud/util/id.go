package util

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// GenerateID creates a unique identifier with the given prefix.
// Format: prefix_<24 hex chars> (e.g. "usr_a1b2c3d4e5f6a1b2c3d4e5f6")
func GenerateID(prefix string) (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate ID: %w", err)
	}
	return prefix + "_" + hex.EncodeToString(b), nil
}
