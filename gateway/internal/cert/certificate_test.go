package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestGenerateGatewayPrivateKeyUsesECDSAP256(t *testing.T) {
	key, err := GenerateGatewayPrivateKey()
	if err != nil {
		t.Fatalf("GenerateGatewayPrivateKey() error = %v", err)
	}
	if key.Curve != elliptic.P256() {
		t.Fatalf("GenerateGatewayPrivateKey() curve = %v, want P-256", key.Curve)
	}

	keyPEM, err := EncodePrivateKeyPEM(key)
	if err != nil {
		t.Fatalf("EncodePrivateKeyPEM() error = %v", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("EncodePrivateKeyPEM() block = %v", block)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey() error = %v", err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("parsed private key type = %T, want *ecdsa.PrivateKey", parsed)
	}
}

func TestValidateGatewayCertificateAcceptsDualUseCertificate(t *testing.T) {
	now := time.Now()
	cert := &x509.Certificate{
		NotBefore:   now.Add(-time.Minute),
		NotAfter:    now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	if err := ValidateGatewayCertificate(cert); err != nil {
		t.Fatalf("ValidateGatewayCertificate() error = %v", err)
	}
}

func TestValidateGatewayCertificateRejectsSingleUseCertificate(t *testing.T) {
	now := time.Now()
	cert := &x509.Certificate{
		NotBefore:   now.Add(-time.Minute),
		NotAfter:    now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	err := ValidateGatewayCertificate(cert)
	if err == nil {
		t.Fatal("ValidateGatewayCertificate() expected error")
	}
	if !strings.Contains(err.Error(), "serverAuth and clientAuth") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateGatewayCertificateRejectsExpiredCertificate(t *testing.T) {
	now := time.Now()
	cert := &x509.Certificate{
		NotBefore:   now.Add(-2 * time.Hour),
		NotAfter:    now.Add(-time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	err := ValidateGatewayCertificate(cert)
	if err == nil {
		t.Fatal("ValidateGatewayCertificate() accepted expired certificate")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := ValidateGatewayCertificateForRenewal(cert); err != nil {
		t.Fatalf("ValidateGatewayCertificateForRenewal() rejected structurally valid expired certificate: %v", err)
	}
}

func TestValidateGatewayCertificateRejectsNotYetValidCertificate(t *testing.T) {
	now := time.Now()
	cert := &x509.Certificate{
		NotBefore:   now.Add(time.Hour),
		NotAfter:    now.Add(2 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	err := ValidateGatewayCertificate(cert)
	if err == nil {
		t.Fatal("ValidateGatewayCertificate() accepted not-yet-valid certificate")
	}
	if !strings.Contains(err.Error(), "not valid before") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGatewayIdentityFromCertificateReadsPAIdentity(t *testing.T) {
	identityURI, err := url.Parse("spiffe://gateway/organization/org-1/gateway/gw-1")
	if err != nil {
		t.Fatalf("parse identity URI: %v", err)
	}
	identity, err := GatewayIdentityFromCertificate(&x509.Certificate{
		DNSNames: []string{"gateway.example.test", "gateway.internal.test"},
		URIs:     []*url.URL{identityURI},
	})
	if err != nil {
		t.Fatalf("GatewayIdentityFromCertificate() error = %v", err)
	}
	if identity.GatewayID != "gw-1" || identity.OrganizationID != "org-1" || identity.FQDN != "gateway.example.test" {
		t.Fatalf("GatewayIdentityFromCertificate() = %+v", identity)
	}
}

func TestGatewayIdentityFromCertificateRequiresFQDN(t *testing.T) {
	identityURI, err := url.Parse("spiffe://gateway/organization/org-1/gateway/gw-1")
	if err != nil {
		t.Fatalf("parse identity URI: %v", err)
	}
	_, err = GatewayIdentityFromCertificate(&x509.Certificate{URIs: []*url.URL{identityURI}})
	if err == nil {
		t.Fatal("GatewayIdentityFromCertificate() accepted identity without DNS SAN")
	}
	if !strings.Contains(err.Error(), "FQDN") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGatewayIdentityFromCertificateRejectsInvalidOrganizationPath(t *testing.T) {
	identityURI, err := url.Parse("spiffe://gateway/account/organization-1/gateway/gw-1")
	if err != nil {
		t.Fatalf("parse identity URI: %v", err)
	}
	if _, err := GatewayIdentityFromCertificate(&x509.Certificate{URIs: []*url.URL{identityURI}}); err == nil {
		t.Fatal("GatewayIdentityFromCertificate() accepted malformed organization identity")
	}
}
