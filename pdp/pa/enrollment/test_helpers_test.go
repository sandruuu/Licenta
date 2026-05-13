package enrollment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"

	"pdp/store"
)

func newEnrollmentTestStore(t *testing.T) *store.Store {
	t.Helper()
	dataStore := store.New(t.TempDir())
	if err := dataStore.InitDB(); err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() {
		if err := dataStore.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	})
	return dataStore
}

type testCertificateAuthority struct {
	t              *testing.T
	key            *ecdsa.PrivateKey
	certificate    *x509.Certificate
	serial         int64
	roles          []string
	revokedSerials []string
}

func newTestCertificateAuthority(t *testing.T) *testCertificateAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	return &testCertificateAuthority{
		t:   t,
		key: key,
		certificate: &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "test-ca"},
			NotBefore:             time.Now().Add(-time.Minute),
			NotAfter:              time.Now().Add(time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  true,
		},
	}
}

func (a *testCertificateAuthority) signCSR(csrPEM []byte, validDays int, role string) ([]byte, error) {
	a.roles = append(a.roles, role)
	csr, _, err := ParseCSR(string(csrPEM))
	if err != nil {
		return nil, err
	}
	a.serial++
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:   big.NewInt(a.serial),
		Subject:        csr.Subject,
		DNSNames:       csr.DNSNames,
		EmailAddresses: csr.EmailAddresses,
		URIs:           csr.URIs,
		NotBefore:      now.Add(-time.Minute),
		NotAfter:       now.Add(time.Duration(validDays) * 24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, a.certificate, csr.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}

func (a *testCertificateAuthority) revokeCertificate(serial, _ string, _ string, _ time.Time) {
	a.revokedSerials = append(a.revokedSerials, serial)
}

func testEnrollmentCSRPEM(t *testing.T, commonName, email string) string {
	t.Helper()
	return testEnrollmentCSRPEMWithKey(t, testEnrollmentKey(t), commonName, email)
}

func testEnrollmentKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func testEnrollmentCSRPEMWithKey(t *testing.T, key *ecdsa.PrivateKey, commonName, email string) string {
	t.Helper()
	request := &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}
	if email != "" {
		request.EmailAddresses = []string{email}
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, request, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

func testEnrollmentCSRPEMWithDeviceURI(t *testing.T, key *ecdsa.PrivateKey, commonName, deviceID, email string) string {
	t.Helper()
	request := &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}
	deviceURI, err := url.Parse(DeviceIdentityURI(deviceID))
	if err != nil {
		t.Fatalf("parse device URI: %v", err)
	}
	request.URIs = []*url.URL{deviceURI}
	if email != "" {
		request.EmailAddresses = []string{email}
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, request, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}
