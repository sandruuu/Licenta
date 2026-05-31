package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"
)

// TOTP implements the Time-based One-Time Password algorithm (RFC 6238)
// using the widely supported HMAC-SHA1 default with 30-second time steps and
// 6-digit codes.
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
	valid, _, err := ValidateTOTPCodeWithCounter(secret, code, time.Now())
	return valid, err
}

func ValidateTOTPCodeWithCounter(secret, code string, now time.Time) (bool, int64, error) {
	code = strings.TrimSpace(code)
	if len(code) != TOTPDigits {
		return false, 0, nil
	}
	if now.IsZero() {
		now = time.Now()
	}

	// Check current time step and adjacent steps (to handle clock drift)
	baseCounter := now.Unix() / TOTPPeriod
	for i := -TOTPSkew; i <= TOTPSkew; i++ {
		counter := baseCounter + int64(i)
		if counter < 0 {
			continue
		}
		expected, err := GenerateTOTPCode(secret, time.Unix(counter*TOTPPeriod, 0))
		if err != nil {
			return false, 0, err
		}
		if hmac.Equal([]byte(expected), []byte(code)) {
			return true, counter, nil
		}
	}

	return false, 0, nil
}

// BuildTOTPURI constructs an otpauth:// URI for QR code generation
// This URI can be scanned by authenticator apps to enroll the secret
func BuildTOTPURI(secret, issuer, accountName string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		urlEncode(issuer),
		urlEncode(accountName),
		secret,
		urlEncode(issuer),
		TOTPDigits,
		TOTPPeriod,
	)
}

// BuildTOTPQRCodeImage renders an otpauth URI as an embedded PNG data URL.
func BuildTOTPQRCodeImage(uri string) (string, error) {
	png, err := qrcode.Encode(strings.TrimSpace(uri), qrcode.Medium, 224)
	if err != nil {
		return "", fmt.Errorf("generate TOTP QR code: %w", err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}

// generateHOTP implements HOTP (RFC 4226) using HMAC-SHA1
func generateHOTP(key []byte, counter uint64) int {
	// Step 1: Generate HMAC-SHA1 value
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, key)
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
