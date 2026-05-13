package enrollment

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"
)

const (
	deviceIdentityURIScheme = "spiffe"
	deviceIdentityURIHost   = "ztna.local"
	deviceIdentityURIPath   = "/device/"
)

func DeviceIdentityURI(deviceID string) string {
	u := url.URL{
		Scheme: deviceIdentityURIScheme,
		Host:   deviceIdentityURIHost,
		Path:   deviceIdentityURIPath + strings.TrimSpace(deviceID),
	}
	return u.String()
}

func ValidateCSRDeviceIdentity(csr *x509.CertificateRequest, deviceID string) error {
	if csr == nil {
		return fmt.Errorf("CSR is required")
	}
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return fmt.Errorf("device_id is required")
	}
	if strings.TrimSpace(csr.Subject.CommonName) == deviceID {
		return nil
	}
	for _, uri := range csr.URIs {
		if DeviceIDFromIdentityURI(uri) == deviceID {
			return nil
		}
	}
	return fmt.Errorf("CSR identity must include device_id in CommonName or %s URI SAN", DeviceIdentityURI(deviceID))
}

func CertificateDeviceID(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	for _, uri := range cert.URIs {
		if id := DeviceIDFromIdentityURI(uri); id != "" {
			return id
		}
	}
	return strings.TrimSpace(cert.Subject.CommonName)
}

func DeviceIDFromIdentityURI(uri *url.URL) string {
	if uri == nil {
		return ""
	}
	if !strings.EqualFold(uri.Scheme, deviceIdentityURIScheme) || !strings.EqualFold(uri.Host, deviceIdentityURIHost) {
		return ""
	}
	escapedPath := uri.EscapedPath()
	if !strings.HasPrefix(escapedPath, deviceIdentityURIPath) {
		return ""
	}
	value, err := url.PathUnescape(strings.TrimPrefix(escapedPath, deviceIdentityURIPath))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(value)
}
