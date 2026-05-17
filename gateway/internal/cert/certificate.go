package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type GatewayIdentity struct {
	GatewayID      string
	OrganizationID string
	FQDN           string
}

func GenerateGatewayPrivateKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate Gateway ECDSA P-256 key: %w", err)
	}
	return key, nil
}

func EncodePrivateKeyPEM(privateKey any) ([]byte, error) {
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func LoadGatewayKeyPair(certPath, keyPath string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf := cert.Leaf
	if leaf == nil {
		if len(cert.Certificate) == 0 {
			return tls.Certificate{}, fmt.Errorf("gateway certificate chain is empty")
		}
		leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("parse gateway certificate: %w", err)
		}
	}
	cert.Leaf = leaf
	return cert, nil
}

func LoadGatewayKeyPairAndValidateCert(certPath, keyPath string) (tls.Certificate, error) {
	cert, err := LoadGatewayKeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := ValidateGatewayCertificate(cert.Leaf); err != nil {
		return tls.Certificate{}, err
	}
	return cert, nil
}

func ValidateGatewayCertificateForRenewal(cert *x509.Certificate) error {
	return validateGatewayCertificateProfile(cert)
}

func ValidateGatewayCertificate(cert *x509.Certificate) error {
	if err := validateGatewayCertificateProfile(cert); err != nil {
		return err
	}
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("gateway certificate is not valid before %s", cert.NotBefore.Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("gateway certificate expired on %s", cert.NotAfter.Format(time.RFC3339))
	}
	return nil
}

func GatewayCertificateExpired(cert *x509.Certificate) bool {
	return cert != nil && time.Now().After(cert.NotAfter)
}

func validateGatewayCertificateProfile(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("gateway certificate is required")
	}
	if cert.IsCA {
		return fmt.Errorf("gateway certificate must be an end-entity certificate, not a CA")
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("gateway certificate must allow digitalSignature key usage")
	}
	if len(cert.ExtKeyUsage) == 0 {
		return fmt.Errorf("gateway certificate must include serverAuth and clientAuth extended key usages")
	}
	if !hasExtKeyUsage(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) || !hasExtKeyUsage(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return fmt.Errorf("gateway certificate must include both serverAuth and clientAuth extended key usages")
	}
	return nil
}

func GatewayExtendedKeyUsageExtension() (pkix.Extension, error) {
	value, err := asn1.Marshal([]asn1.ObjectIdentifier{
		{1, 3, 6, 1, 5, 5, 7, 3, 1}, // serverAuth
		{1, 3, 6, 1, 5, 5, 7, 3, 2}, // clientAuth
	})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("build gateway EKU extension: %w", err)
	}
	return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: value}, nil
}

func ParseGatewayCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("gateway certificate PEM is required")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse gateway certificate: %w", err)
	}
	return cert, nil
}

func GatewayIdentityFromCertificate(cert *x509.Certificate) (GatewayIdentity, error) {
	if cert == nil {
		return GatewayIdentity{}, fmt.Errorf("gateway certificate is required")
	}
	for _, identityURI := range cert.URIs {
		identity, ok := gatewayIdentityFromURI(identityURI)
		if ok {
			for _, name := range cert.DNSNames {
				if strings.TrimSpace(name) != "" {
					identity.FQDN = strings.TrimSpace(name)
					break
				}
			}
			if identity.FQDN == "" {
				return GatewayIdentity{}, fmt.Errorf("gateway certificate does not contain gateway FQDN")
			}
			return identity, nil
		}
	}
	return GatewayIdentity{}, fmt.Errorf("gateway certificate does not contain gateway identity")
}

func gatewayIdentityFromURI(identityURI *url.URL) (GatewayIdentity, bool) {
	if identityURI == nil || identityURI.Scheme != "spiffe" {
		return GatewayIdentity{}, false
	}
	parts := strings.Split(strings.Trim(identityURI.EscapedPath(), "/"), "/")
	if len(parts) != 4 || parts[0] != "organization" || parts[2] != "gateway" {
		return GatewayIdentity{}, false
	}
	organizationID, err := url.PathUnescape(parts[1])
	if err != nil || strings.TrimSpace(organizationID) == "" {
		return GatewayIdentity{}, false
	}
	gatewayID, err := url.PathUnescape(parts[3])
	if err != nil || strings.TrimSpace(gatewayID) == "" {
		return GatewayIdentity{}, false
	}
	return GatewayIdentity{
		GatewayID:      strings.TrimSpace(gatewayID),
		OrganizationID: strings.TrimSpace(organizationID),
	}, true
}

func hasExtKeyUsage(usages []x509.ExtKeyUsage, wanted x509.ExtKeyUsage) bool {
	for _, usage := range usages {
		if usage == x509.ExtKeyUsageAny || usage == wanted {
			return true
		}
	}
	return false
}
