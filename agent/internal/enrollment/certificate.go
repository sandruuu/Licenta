package enrollment

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"
)

func CertificateSHA256(certPEM []byte) (string, error) {
	cert, err := firstCertificate(certPEM)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(digest[:]), nil
}

func CertificateNotAfter(certPEM []byte) (time.Time, error) {
	cert, err := firstCertificate(certPEM)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter.UTC(), nil
}

func certificateDERs(data []byte) ([][]byte, error) {
	var ders [][]byte
	rest := data
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return nil, fmt.Errorf("parse certificate PEM: %w", err)
			}
			ders = append(ders, append([]byte(nil), block.Bytes...))
		}
		rest = remaining
	}
	if len(ders) > 0 {
		return ders, nil
	}
	if cert, err := x509.ParseCertificate(data); err == nil {
		return [][]byte{cert.Raw}, nil
	}
	return nil, fmt.Errorf("certificate PEM or DER is required")
}

func firstCertificate(data []byte) (*x509.Certificate, error) {
	ders, err := certificateDERs(data)
	if err != nil {
		return nil, err
	}
	if len(ders) == 0 {
		return nil, fmt.Errorf("certificate is required")
	}
	cert, err := x509.ParseCertificate(ders[0])
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}
