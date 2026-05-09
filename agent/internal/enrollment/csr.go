package enrollment

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/mail"
	"strings"
)

type CSRIdentity struct {
	DeviceID  string
	Hostname  string
	UserEmail string
}

func PublicKeyFingerprint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	digest := sha256.Sum256(der)
	return hex.EncodeToString(digest[:]), nil
}

func CreateCSRWithIdentity(signer crypto.Signer, identity CSRIdentity) ([]byte, error) {
	if signer == nil {
		return nil, fmt.Errorf("signer is required")
	}
	deviceID := strings.TrimSpace(identity.DeviceID)
	if deviceID == "" {
		return nil, fmt.Errorf("device_id is required")
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   deviceID,
			Organization: []string{"ZeroTrust Endpoint"},
		},
	}
	if hostname := strings.TrimSpace(identity.Hostname); hostname != "" {
		template.DNSNames = []string{hostname}
	}
	if email, ok, err := emailSAN(identity.UserEmail); err != nil {
		return nil, err
	} else if ok {
		template.EmailAddresses = []string{email}
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

func emailSAN(value string) (string, bool, error) {
	value = strings.TrimSpace(value)
	if value == "" || !strings.Contains(value, "@") {
		return "", false, nil
	}
	addr, err := mail.ParseAddress(value)
	if err != nil || addr == nil || addr.Name != "" || addr.Address != value {
		return "", false, fmt.Errorf("invalid user email for CSR SAN")
	}
	return addr.Address, true, nil
}
