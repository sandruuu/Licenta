package certificates

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

func SHA256(certificate tls.Certificate) (string, error) {
	if certificate.Leaf != nil && len(certificate.Leaf.Raw) > 0 {
		digest := sha256.Sum256(certificate.Leaf.Raw)
		return hex.EncodeToString(digest[:]), nil
	}
	if len(certificate.Certificate) == 0 || len(certificate.Certificate[0]) == 0 {
		return "", errors.New("Machine Store endpoint certificate has no leaf material")
	}
	digest := sha256.Sum256(certificate.Certificate[0])
	return hex.EncodeToString(digest[:]), nil
}

func NotAfter(certificate tls.Certificate) (time.Time, error) {
	if certificate.Leaf != nil && !certificate.Leaf.NotAfter.IsZero() {
		return certificate.Leaf.NotAfter.UTC(), nil
	}
	if len(certificate.Certificate) == 0 || len(certificate.Certificate[0]) == 0 {
		return time.Time{}, errors.New("Machine Store endpoint certificate has no leaf material")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return time.Time{}, fmt.Errorf("parse Machine Store endpoint certificate: %w", err)
	}
	return leaf.NotAfter.UTC(), nil
}
