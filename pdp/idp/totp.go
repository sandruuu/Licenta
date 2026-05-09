package idp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"
)

// TOTP implements the Time-based One-Time Password algorithm (RFC 6238)
// using HMAC-SHA256 with 30-second time steps and 6-digit codes.
//
// This is compatible with Google Authenticator, Microsoft Authenticator,
// FreeOTP, and other standard TOTP applications.

const (
	// TOTPDigits is the number of digits in the generated code
	TOTPDigits = 6

	// TOTPPeriod is the time step in seconds
	TOTPPeriod = 30

	// TOTPSecretLength is the length of the secret key in bytes (before base32 encoding)
	TOTPSecretLength = 20

	// TOTPSkew allows codes from adjacent time steps (±1) to compensate for clock drift
	TOTPSkew = 1
)

// GenerateTOTPSecret generates a new random TOTP secret (base32-encoded)
func GenerateTOTPSecret() (string, error) {
	secret := make([]byte, TOTPSecretLength)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate random secret: %w", err)
	}

	// Encode to base32 without padding (standard for TOTP)
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	return encoded, nil
}

// GenerateTOTPCode generates a TOTP code for the given secret and time
func GenerateTOTPCode(secret string, t time.Time) (string, error) {
	// Decode the base32 secret
	key, err := decodeSecret(secret)
	if err != nil {
		return "", fmt.Errorf("decode secret: %w", err)
	}

	// Calculate the time counter (number of time steps since Unix epoch)
	counter := uint64(t.Unix()) / TOTPPeriod

	// Generate HOTP value using HMAC-SHA1
	code := generateHOTP(key, counter)

	// Format to 6 digits with leading zeros
	return fmt.Sprintf("%0*d", TOTPDigits, code), nil
}

// ValidateTOTPCode validates a TOTP code against a secret, allowing for clock skew
func ValidateTOTPCode(secret, code string) (bool, error) {
	if len(code) != TOTPDigits {
		return false, nil
	}

	now := time.Now()

	// Check current time step and adjacent steps (to handle clock drift)
	for i := -TOTPSkew; i <= TOTPSkew; i++ {
		t := now.Add(time.Duration(i*TOTPPeriod) * time.Second)
		expected, err := GenerateTOTPCode(secret, t)
		if err != nil {
			return false, err
		}
		if hmac.Equal([]byte(expected), []byte(code)) {
			return true, nil
		}
	}

	return false, nil
}

// BuildTOTPURI constructs an otpauth:// URI for QR code generation
// This URI can be scanned by authenticator apps to enroll the secret
func BuildTOTPURI(secret, issuer, accountName string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA256&digits=%d&period=%d",
		urlEncode(issuer),
		urlEncode(accountName),
		secret,
		urlEncode(issuer),
		TOTPDigits,
		TOTPPeriod,
	)
}

// generateHOTP implements HOTP (RFC 4226) using HMAC-SHA256
func generateHOTP(key []byte, counter uint64) int {
	// Step 1: Generate HMAC-SHA256 value
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha256.New, key)
	mac.Write(buf)
	hash := mac.Sum(nil)

	// Step 2: Dynamic truncation
	// Use the last nibble of the hash to determine the offset
	offset := hash[len(hash)-1] & 0x0f

	// Extract 4 bytes starting at the offset
	truncated := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff

	// Step 3: Compute TOTP code as truncated value mod 10^digits
	code := int(truncated % uint32(math.Pow10(TOTPDigits)))

	return code
}

// decodeSecret decodes a base32-encoded TOTP secret
func decodeSecret(secret string) ([]byte, error) {
	// Normalize: uppercase and remove spaces
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))

	// Add padding if necessary
	if m := len(secret) % 8; m != 0 {
		secret += strings.Repeat("=", 8-m)
	}

	return base32.StdEncoding.DecodeString(secret)
}

// urlEncode performs simple percent-encoding for URI components
func urlEncode(s string) string {
	var result strings.Builder
	for _, c := range s {
		switch {
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'):
			result.WriteRune(c)
		case c == '-' || c == '_' || c == '.' || c == '~':
			result.WriteRune(c)
		default:
			result.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return result.String()
}
