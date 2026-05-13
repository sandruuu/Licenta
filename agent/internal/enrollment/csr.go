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
	"net/url"
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
			CommonName:   deviceCommonName(deviceID),
			Organization: []string{"ZeroTrust Endpoint"},
		},
	}
	deviceURI, err := url.Parse(deviceIdentityURI(deviceID))
	if err != nil {
		return nil, fmt.Errorf("build device URI SAN: %w", err)
	}
	template.URIs = []*url.URL{deviceURI}
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

func deviceIdentityURI(deviceID string) string {
	u := url.URL{
		Scheme: "spiffe",
		Host:   "ztna.local",
		Path:   "/device/" + strings.TrimSpace(deviceID),
	}
	return u.String()
}

func deviceCommonName(deviceID string) string {
	deviceID = strings.TrimSpace(deviceID)
	if isDNSLabel(deviceID) {
		return deviceID
	}
	const prefix = "ztna-device-"
	suffix := strings.ToLower(deviceID)
	if max := 63 - len(prefix); len(suffix) > max {
		suffix = suffix[:max]
	}
	suffix = strings.Trim(suffix, "-")
	if suffix == "" {
		return strings.TrimSuffix(prefix, "-")
	}
	return prefix + suffix
}

func isDNSLabel(value string) bool {
	if len(value) == 0 || len(value) > 63 {
		return false
	}
	if value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' {
			continue
		}
		if r >= 'A' && r <= 'Z' {
			continue
		}
		if r >= '0' && r <= '9' {
			continue
		}
		if r == '-' {
			continue
		}
		return false
	}
	return true
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
