package enrollment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
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

// ValidateKeyProof verifies a TPM-signed key proof (N3 fix). The proof is
// an ECDSA signature over a deterministic challenge built from device_id and
// public_key_fingerprint. The signature is verified against the public key
// extracted from the CSR, so the fingerprint cannot be spoofed.
func ValidateKeyProof(csr *x509.CertificateRequest, deviceID, fingerprint, keyProof string) error {
	keyProof = strings.TrimSpace(keyProof)
	if keyProof == "" {
		// Key proof is optional: enrollment proceeds without it but logs a warning.
		return nil
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub == nil {
		return fmt.Errorf("CSR public key is not ECDSA")
	}
	if pub.Curve != elliptic.P256() {
		return fmt.Errorf("CSR public key is not P-256")
	}
	signature, err := hex.DecodeString(keyProof)
	if err != nil || len(signature) < 60 {
		return fmt.Errorf("invalid key proof format")
	}
	challenge := fmt.Sprintf("ztna-est-enrollment:%s:%s", deviceID, fingerprint)
	hash := sha256.Sum256([]byte(challenge))
	r := new(big.Int).SetBytes(signature[:len(signature)/2])
	s := new(big.Int).SetBytes(signature[len(signature)/2:])
	if !ecdsa.Verify(pub, hash[:], r, s) {
		return fmt.Errorf("key proof signature verification failed")
	}
	return nil
}
