package enrollment

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
)

func NormalizeComponent(component string) string {
	switch strings.ToLower(strings.TrimSpace(component)) {
	case "", "device", "endpoint", "tunnel", "health":
		return "endpoint"
	default:
		return strings.ToLower(strings.TrimSpace(component))
	}
}

func CanonicalCSRPEM(input string) (string, error) {
	csr, der, err := ParseCSR(input)
	if err != nil {
		return "", err
	}
	if err := csr.CheckSignature(); err != nil {
		return "", fmt.Errorf("CSR signature invalid: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

func ParseCSR(input string) (*x509.CertificateRequest, []byte, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return nil, nil, fmt.Errorf("CSR is required")
	}

	if block, _ := pem.Decode([]byte(trimmed)); block != nil {
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse CSR: %w", err)
		}
		return csr, block.Bytes, nil
	}

	raw := []byte(trimmed)
	if csr, err := x509.ParseCertificateRequest(raw); err == nil {
		return csr, raw, nil
	}

	compact := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, trimmed)
	der, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode CSR PEM/DER/base64")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CSR: %w", err)
	}
	return csr, der, nil
}

func ComputeCSRFingerprint(csrPEM string) (string, error) {
	csr, _, err := ParseCSR(csrPEM)
	if err != nil {
		return "", err
	}
	if err := csr.CheckSignature(); err != nil {
		return "", fmt.Errorf("CSR signature invalid: %w", err)
	}
	der, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	fingerprint := sha256.Sum256(der)
	return hex.EncodeToString(fingerprint[:]), nil
}

func ValidateCSREmailIdentity(csr *x509.CertificateRequest, username string) error {
	if csr == nil || len(csr.EmailAddresses) == 0 {
		return nil
	}
	expected := strings.TrimSpace(username)
	if !strings.Contains(expected, "@") {
		return fmt.Errorf("CSR email SAN is not allowed for this enrollment identity")
	}
	for _, email := range csr.EmailAddresses {
		if !strings.EqualFold(strings.TrimSpace(email), expected) {
			return fmt.Errorf("CSR email SAN must match enrollment identity")
		}
	}
	return nil
}

func ShortFingerprint(value string) string {
	if len(value) <= 16 {
		return value
	}
	return value[:16]
}
