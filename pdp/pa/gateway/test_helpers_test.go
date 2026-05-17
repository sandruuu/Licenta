package gateway

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"sync"
	"testing"
	"time"

	"pdp/models"
	"pdp/store"
)

func gatewayTokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func newGatewayTestStore(t *testing.T) *store.Store {
	t.Helper()
	dataStore := store.New(t.TempDir())
	if err := dataStore.InitDB(); err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { _ = dataStore.Close() })
	return dataStore
}

const gatewayTestTenantID = "tenant-1"

func seedGatewayTenant(dataStore *store.Store) {
	now := time.Now()
	dataStore.SaveTenant(&models.Tenant{
		ID:        gatewayTestTenantID,
		Name:      "Test Tenant",
		Domain:    "example.test",
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	})
}

func newGatewayTestService(t *testing.T, dataStore *store.Store, now time.Time) *Service {
	t.Helper()
	ca := newGatewayTestCA(t)
	service := NewService(dataStore, "gateway-role")
	service.SetCertificateAuthority(ca.sign, nil)
	service.now = func() time.Time { return now }
	return service
}

type gatewayTestCA struct {
	key    *rsa.PrivateKey
	cert   *x509.Certificate
	mu     sync.Mutex
	serial int64
	role   string
}

func newGatewayTestCA(t *testing.T) *gatewayTestCA {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Gateway CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return &gatewayTestCA{key: key, cert: cert, serial: 100}
}

func (ca *gatewayTestCA) sign(csrPEM []byte, validDays int, role string, profile CertificateProfile) ([]byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}
	ca.mu.Lock()
	ca.serial++
	serial := ca.serial
	ca.role = role
	ca.mu.Unlock()
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: profile.CommonName},
		DNSNames:     append([]string(nil), profile.DNSNames...),
		URIs:         certificateProfileURIs(profile.URISANs),
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Duration(validDays) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func certificateProfileURIs(values []string) []*url.URL {
	uris := make([]*url.URL, 0, len(values))
	for _, value := range values {
		identityURI, err := url.Parse(value)
		if err != nil {
			panic(err)
		}
		uris = append(uris, identityURI)
	}
	return uris
}

func (ca *gatewayTestCA) lastRole() string {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return ca.role
}

func newGatewayCSR(t *testing.T, tenantID, gatewayID, fqdn string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	identityURI, err := url.Parse(GatewayIdentityURI(tenantID, gatewayID))
	if err != nil {
		t.Fatalf("parse gateway identity URI: %v", err)
	}
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: gatewayID},
		DNSNames: []string{fqdn},
		URIs:     []*url.URL{identityURI},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func newBareGatewayCSR(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func parseGatewayTestCertificate(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("certificate PEM is invalid")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}
