package enrollment

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCreateCSRWithIdentityAddsSANs(t *testing.T) {
	key := newTestKey(t)
	csrPEM, err := CreateCSRWithIdentity(key, CSRIdentity{DeviceID: "device-1", Hostname: "host-1", UserEmail: "user@example.com"})
	if err != nil {
		t.Fatalf("CreateCSRWithIdentity returned error: %v", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatalf("CSR was not PEM encoded")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificateRequest returned error: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature invalid: %v", err)
	}
	if csr.Subject.CommonName != "device-1" || len(csr.DNSNames) != 1 || csr.DNSNames[0] != "host-1" || len(csr.EmailAddresses) != 1 || csr.EmailAddresses[0] != "user@example.com" {
		t.Fatalf("CSR identity = subject=%+v dns=%v emails=%v", csr.Subject, csr.DNSNames, csr.EmailAddresses)
	}
	if _, err := CreateCSRWithIdentity(key, CSRIdentity{DeviceID: "device-1", UserEmail: "User <user@example.com>"}); err == nil {
		t.Fatalf("CreateCSRWithIdentity accepted display-name email")
	}
}

func TestSimpleEnrollWithTokenPostsESTRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/.well-known/est/ztna/simpleenroll" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer enrollment.jwt" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("X-ZTNA-Enrollment-Nonce") != "nonce-1" {
			t.Fatalf("nonce header = %q", r.Header.Get("X-ZTNA-Enrollment-Nonce"))
		}
		var request estEnrollmentRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("Decode body returned error: %v", err)
		}
		if request.DeviceID != "device-1" || request.Component != endpointComponent || request.Hostname != "host-1" || !strings.Contains(request.CSRPEM, "BEGIN CERTIFICATE REQUEST") || request.PublicKeyFingerprint != "fp-1" {
			t.Fatalf("request body = %+v", request)
		}
		_ = json.NewEncoder(w).Encode(estEnrollmentResponse{ID: "enroll-1", Status: "approved", CertPEM: string(testCertificatePEM(t, "device-1")), CAPEM: string(testCertificatePEM(t, "ca"))})
	}))
	defer server.Close()

	result, err := SimpleEnrollWithToken(context.Background(), TokenEnrollmentConfig{CloudURL: server.URL, Token: "enrollment.jwt", Nonce: "nonce-1", DeviceID: "device-1", Hostname: "host-1", HTTPClient: server.Client()}, []byte("-----BEGIN CERTIFICATE REQUEST-----\nabc\n-----END CERTIFICATE REQUEST-----\n"), "fp-1")
	if err != nil {
		t.Fatalf("SimpleEnrollWithToken returned error: %v", err)
	}
	if result.ID != "enroll-1" || len(result.CertPEM) == 0 || len(result.CAPEM) == 0 {
		t.Fatalf("result = %+v", result)
	}
}

func TestRunnerCreatesCSRCallsESTAndInstaller(t *testing.T) {
	key := newTestKey(t)
	fingerprint, err := PublicKeyFingerprint(key.Public())
	if err != nil {
		t.Fatalf("PublicKeyFingerprint returned error: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request estEnrollmentRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("Decode body returned error: %v", err)
		}
		block, _ := pem.Decode([]byte(request.CSRPEM))
		if block == nil {
			t.Fatalf("CSR was not PEM encoded")
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatalf("ParseCertificateRequest returned error: %v", err)
		}
		if csr.Subject.CommonName != "device-1" || len(csr.DNSNames) != 1 || csr.DNSNames[0] != "host-1" || len(csr.EmailAddresses) != 1 || csr.EmailAddresses[0] != "user@example.com" {
			t.Fatalf("CSR = subject=%+v dns=%v emails=%v", csr.Subject, csr.DNSNames, csr.EmailAddresses)
		}
		if request.PublicKeyFingerprint != fingerprint {
			t.Fatalf("fingerprint = %q, want %q", request.PublicKeyFingerprint, fingerprint)
		}
		_ = json.NewEncoder(w).Encode(estEnrollmentResponse{ID: "enroll-1", Status: "approved", CertPEM: string(testCertificatePEM(t, "device-1")), CAPEM: string(testCertificatePEM(t, "ca"))})
	}))
	defer server.Close()
	installer := &fakeCertificateInstaller{}
	runner, err := NewRunner(RunnerConfig{CloudURL: server.URL, Hostname: "host-1", HTTPClient: server.Client(), KeyProvider: fakeKeyProvider{key: key}, Installer: installer})
	if err != nil {
		t.Fatalf("NewRunner returned error: %v", err)
	}
	result, err := runner.Enroll(context.Background(), RunnerInput{Token: "enrollment.jwt", Nonce: "nonce-1", DeviceID: "device-1", KeyName: "ZTNA_DeviceKey_S-1-5-21-1", KeyProvider: "Microsoft Platform Crypto Provider", UserEmail: "user@example.com"})
	if err != nil {
		t.Fatalf("Enroll returned error: %v", err)
	}
	if result.EnrollmentID != "enroll-1" || result.CertificateSHA256 == "" || result.CertificateNotAfter.IsZero() {
		t.Fatalf("result = %+v", result)
	}
	if !installer.called || installer.request.KeyName != "ZTNA_DeviceKey_S-1-5-21-1" || installer.request.KeyProvider != "Microsoft Platform Crypto Provider" {
		t.Fatalf("installer = %+v", installer)
	}
}

func TestRenewWithMTLSPresentsClientCertificate(t *testing.T) {
	key := newTestKey(t)
	currentCertificate := testTLSCertificate(t, "device-1", key)
	csrPEM, err := CreateCSRWithIdentity(key, CSRIdentity{DeviceID: "device-1", Hostname: "host-1"})
	if err != nil {
		t.Fatalf("CreateCSRWithIdentity returned error: %v", err)
	}
	fingerprint, err := PublicKeyFingerprint(key.Public())
	if err != nil {
		t.Fatalf("PublicKeyFingerprint returned error: %v", err)
	}
	sawClientCertificate := false
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/enroll/renew" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			t.Fatalf("renewal request did not present a client certificate")
		}
		sawClientCertificate = true
		var request estEnrollmentRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("Decode body returned error: %v", err)
		}
		if request.DeviceID != "device-1" || request.Component != endpointComponent || request.Hostname != "host-1" || !strings.Contains(request.CSRPEM, "BEGIN CERTIFICATE REQUEST") || request.PublicKeyFingerprint != fingerprint {
			t.Fatalf("request body = %+v", request)
		}
		_ = json.NewEncoder(w).Encode(estEnrollmentResponse{ID: "renew-1", Status: "approved", CertPEM: string(testCertificatePEM(t, "device-1")), CAPEM: string(testCertificatePEM(t, "ca"))})
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()

	caFile := filepath.Join(t.TempDir(), "server-ca.pem")
	serverCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caFile, serverCAPEM, 0600); err != nil {
		t.Fatalf("write server CA: %v", err)
	}

	result, err := RenewWithMTLS(context.Background(), RenewalConfig{
		CloudURL:             server.URL,
		CAFile:               caFile,
		DeviceID:             "device-1",
		Hostname:             "host-1",
		CSRPEM:               csrPEM,
		PublicKeyFingerprint: fingerprint,
		CurrentCertificate:   currentCertificate,
	})
	if err != nil {
		t.Fatalf("RenewWithMTLS returned error: %v", err)
	}
	if !sawClientCertificate {
		t.Fatalf("server did not observe a client certificate")
	}
	if result.ID != "renew-1" || len(result.CertPEM) == 0 || len(result.CAPEM) == 0 {
		t.Fatalf("result = %+v", result)
	}
}

type fakeKeyProvider struct {
	key *ecdsa.PrivateKey
}

func (provider fakeKeyProvider) EnsureSigningKey(context.Context, string) (crypto.Signer, error) {
	return provider.key, nil
}

type fakeCertificateInstaller struct {
	called  bool
	request InstallRequest
}

func (installer *fakeCertificateInstaller) InstallCertificate(_ context.Context, request InstallRequest) (InstallResult, error) {
	installer.called = true
	installer.request = request
	return InstallResult{Installed: true, LeafStore: `LocalMachine\My`, CAStore: `LocalMachine\CA`}, nil
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	return key
}

func testCertificatePEM(t *testing.T, commonName string) []byte {
	t.Helper()
	key := newTestKey(t)
	certificate := testTLSCertificate(t, commonName, key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})
}

func testTLSCertificate(t *testing.T, commonName string, key *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate returned error: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate returned error: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}
