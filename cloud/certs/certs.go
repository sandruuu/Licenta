package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"
)

// CertFingerprint returns the SHA-256 fingerprint of a PEM certificate
func CertFingerprint(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:]), nil
}

// CertInfo holds parsed certificate metadata
type CertInfo struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	IsExpired bool      `json:"is_expired"`
	DaysLeft  int       `json:"days_left"`
	DNSNames  []string  `json:"dns_names"`
	SerialNo  string    `json:"serial_no"`
}

// BuildResourceCSR generates a fresh ECDSA P-256 keypair and a PKCS#10
// certificate signing request for the given domain. The CSR is meant to be
// submitted to the external PKI (HashiCorp Vault) for signing under the
// resource role. Returns PEM-encoded CSR and PEM-encoded private key.
func BuildResourceCSR(domain string) (csrPEM []byte, keyPEM []byte, err error) {
	if domain == "" {
		return nil, nil, fmt.Errorf("domain cannot be empty")
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %w", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{"ZeroTrust Cloud"},
		},
		DNSNames: []string{domain},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CSR: %w", err)
	}
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return csrPEM, keyPEM, nil
}

// ParseCertPEM parses a PEM-encoded certificate and returns metadata
func ParseCertPEM(certPEM string) (*CertInfo, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	now := time.Now()
	daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)

	return &CertInfo{
		Subject:   cert.Subject.CommonName,
		Issuer:    cert.Issuer.CommonName,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		IsExpired: now.After(cert.NotAfter),
		DaysLeft:  daysLeft,
		DNSNames:  cert.DNSNames,
		SerialNo:  cert.SerialNumber.String(),
	}, nil
}
