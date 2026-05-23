package pki

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// EnsureCAPEMCompatible prevents accidental PKI CA rotation from silently
// invalidating already enrolled devices and gateways.
func EnsureCAPEMCompatible(existingCAPath string, currentCAPEM []byte) error {
	path := strings.TrimSpace(existingCAPath)
	if path == "" {
		return nil
	}

	existingCAPEM, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read saved CA %s: %w", path, err)
	}

	existingCert, err := firstCertificate(existingCAPEM)
	if err != nil {
		return fmt.Errorf("parse saved CA %s: %w", path, err)
	}
	currentCert, err := firstCertificate(currentCAPEM)
	if err != nil {
		return fmt.Errorf("parse current Vault CA: %w", err)
	}

	if bytes.Equal(existingCert.Raw, currentCert.Raw) {
		return nil
	}

	return fmt.Errorf(
		"Vault PKI CA changed; refusing to overwrite %s because enrolled device and gateway certificates would become invalid (saved_ca_sha256=%s current_ca_sha256=%s)",
		path,
		certificateSHA256(existingCert),
		certificateSHA256(currentCert),
	)
}

func firstCertificate(certPEM []byte) (*x509.Certificate, error) {
	rest := certPEM
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return cert, nil
	}
	return nil, fmt.Errorf("no certificate PEM block found")
}

func certificateSHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}
