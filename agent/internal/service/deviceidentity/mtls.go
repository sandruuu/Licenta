package deviceidentity

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type MachineCertificateOptions struct {
	DeviceID    string
	KeyName     string
	KeyProvider string
	Clock       func() time.Time
}

func validateMachineCertificateOptions(options MachineCertificateOptions) (MachineCertificateOptions, error) {
	options.DeviceID = strings.TrimSpace(options.DeviceID)
	options.KeyName = strings.TrimSpace(options.KeyName)
	options.KeyProvider = strings.TrimSpace(options.KeyProvider)
	if options.DeviceID == "" {
		return options, errors.New("device_id is required")
	}
	if options.KeyName == "" {
		return options, errors.New("key name is required")
	}
	if options.KeyProvider != "" && options.KeyProvider != MicrosoftPlatformCryptoProvider {
		return options, fmt.Errorf("unsupported key provider %q", options.KeyProvider)
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	return options, nil
}

func selectMachineCertificate(candidates []*x509.Certificate, deviceID string, publicKey any, now time.Time) (*x509.Certificate, error) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return nil, errors.New("device_id is required")
	}
	var selected *x509.Certificate
	for _, cert := range candidates {
		if cert == nil {
			continue
		}
		if certificateDeviceID(cert) != deviceID {
			continue
		}
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			continue
		}
		if !certificateAllowsClientAuth(cert) {
			continue
		}
		if publicKey != nil && !publicKeysMatch(cert.PublicKey, publicKey) {
			continue
		}
		if selected == nil || cert.NotAfter.After(selected.NotAfter) {
			selected = cert
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("no valid endpoint client certificate found in LocalMachine\\My for device_id %q", deviceID)
	}
	return selected, nil
}

func certificateDeviceID(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	for _, uri := range cert.URIs {
		if id := deviceIDFromIdentityURI(uri); id != "" {
			return id
		}
	}
	return strings.TrimSpace(cert.Subject.CommonName)
}

func deviceIDFromIdentityURI(uri *url.URL) string {
	if uri == nil {
		return ""
	}
	if !strings.EqualFold(uri.Scheme, "spiffe") || !strings.EqualFold(uri.Host, "agent") {
		return ""
	}
	const prefix = "/device/"
	escapedPath := uri.EscapedPath()
	if !strings.HasPrefix(escapedPath, prefix) {
		return ""
	}
	value, err := url.PathUnescape(strings.TrimPrefix(escapedPath, prefix))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

func certificateAllowsClientAuth(cert *x509.Certificate) bool {
	if cert == nil || len(cert.ExtKeyUsage) == 0 {
		return true
	}
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}

func publicKeysMatch(left, right any) bool {
	leftDER, err := x509.MarshalPKIXPublicKey(left)
	if err != nil {
		return false
	}
	rightDER, err := x509.MarshalPKIXPublicKey(right)
	if err != nil {
		return false
	}
	return bytes.Equal(leftDER, rightDER)
}

func certificateChainDER(leaf *x509.Certificate, issuers []*x509.Certificate) [][]byte {
	if leaf == nil {
		return nil
	}
	chain := [][]byte{leaf.Raw}
	current := leaf
	seen := map[string]bool{string(leaf.RawSubject): true}
	for {
		issuer := findIssuer(current, issuers)
		if issuer == nil || bytes.Equal(issuer.Raw, current.Raw) || seen[string(issuer.RawSubject)] {
			return chain
		}
		chain = append(chain, issuer.Raw)
		seen[string(issuer.RawSubject)] = true
		current = issuer
	}
}

func findIssuer(cert *x509.Certificate, issuers []*x509.Certificate) *x509.Certificate {
	if cert == nil || bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return nil
	}
	for _, candidate := range issuers {
		if candidate == nil || !bytes.Equal(cert.RawIssuer, candidate.RawSubject) {
			continue
		}
		if err := cert.CheckSignatureFrom(candidate); err == nil {
			return candidate
		}
	}
	return nil
}

func tlsCertificateFromMachineStore(signer crypto.PrivateKey, leaf *x509.Certificate, issuers []*x509.Certificate) tls.Certificate {
	return tls.Certificate{
		Certificate: certificateChainDER(leaf, issuers),
		PrivateKey:  signer,
		Leaf:        leaf,
	}
}
