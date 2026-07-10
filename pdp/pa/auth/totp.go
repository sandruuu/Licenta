package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"
)

const (
	TOTPDigits       = 6
	TOTPPeriod       = 30
	TOTPSecretLength = 20
	TOTPSkew         = 1

	totpModulus = 1000000
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

// GenerateTOTPCode generates a TOTP code for the given secret and time.
func GenerateTOTPCode(secret string, t time.Time) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", fmt.Errorf("decode secret: %w", err)
	}

	counter := uint64(t.Unix()) / TOTPPeriod
	code := generateTOTPValue(key, counter)
	return fmt.Sprintf("%0*d", TOTPDigits, code), nil
}

// ValidateTOTPCode validates a TOTP code against a secret, allowing for clock skew.
func ValidateTOTPCode(secret, code string) (bool, error) {
	valid, _, err := validateTOTPCodeAtTime(secret, code, time.Now())
	return valid, err
}

func ValidateTOTPCodeWithCounter(secret, code string, now time.Time) (bool, int64, error) {
	return validateTOTPCodeAtTime(secret, code, now)
}

func validateTOTPCodeAtTime(secret, code string, now time.Time) (bool, int64, error) {
	code = strings.TrimSpace(code)
	if len(code) != TOTPDigits {
		return false, 0, nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return false, 0, fmt.Errorf("decode secret: %w", err)
	}

	baseCounter := now.Unix() / TOTPPeriod
	for i := -TOTPSkew; i <= TOTPSkew; i++ {
		counter := baseCounter + int64(i)
		if counter < 0 {
			continue
		}
		if validTOTPCodeForCounter(key, code, uint64(counter)) {
			return true, counter, nil
		}
	}

	return false, 0, nil
}

func validTOTPCodeForCounter(key []byte, code string, counter uint64) bool {
	expected := fmt.Sprintf("%0*d", TOTPDigits, generateTOTPValue(key, counter))
	return hmac.Equal([]byte(expected), []byte(code))
}

// BuildTOTPURI constructs an otpauth:// URI for QR code generation.
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

func generateTOTPValue(key []byte, counter uint64) int {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	hash := mac.Sum(nil)

	offset := hash[len(hash)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff
	return int(truncated % totpModulus)
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

// urlEncode percent-encodes URI components.
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
