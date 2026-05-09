package endpointidentity

import (
	"context"
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
	"testing"
	"time"
)

func TestCreateCSRUsesEndpointSubjectAndSigner(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	csrPEM, err := CreateCSR(key, "device-1", "host-1")
	if err != nil {
		t.Fatalf("CreateCSR returned error: %v", err)
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatalf("CSR is not PEM encoded")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature invalid: %v", err)
	}
	if csr.Subject.CommonName != "device-1" {
		t.Fatalf("CommonName = %q, want device-1", csr.Subject.CommonName)
	}
	if len(csr.Subject.Organization) != 1 || csr.Subject.Organization[0] != "ZeroTrust Endpoint" {
		t.Fatalf("Organization = %v, want ZeroTrust Endpoint", csr.Subject.Organization)
	}
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "host-1" {
		t.Fatalf("DNSNames = %v, want host-1", csr.DNSNames)
	}
}

func TestCreateCSRWithIdentityAddsEmailSAN(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	csrPEM, err := CreateCSRWithIdentity(key, CSRIdentity{DeviceID: "device-1", Hostname: "host-1", UserEmail: "user@example.com"})
	if err != nil {
		t.Fatalf("CreateCSRWithIdentity returned error: %v", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatalf("CSR is not PEM encoded")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if len(csr.EmailAddresses) != 1 || csr.EmailAddresses[0] != "user@example.com" {
		t.Fatalf("EmailAddresses = %v", csr.EmailAddresses)
	}
	if _, err := CreateCSRWithIdentity(key, CSRIdentity{DeviceID: "device-1", UserEmail: "User <user@example.com>"}); err == nil {
		t.Fatalf("CreateCSRWithIdentity accepted display-name email")
	}
}

func TestPublicKeyFingerprintIsStable(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	one, err := PublicKeyFingerprint(&key.PublicKey)
	if err != nil {
		t.Fatalf("PublicKeyFingerprint returned error: %v", err)
	}
	two, err := PublicKeyFingerprint(&key.PublicKey)
	if err != nil {
		t.Fatalf("PublicKeyFingerprint returned error: %v", err)
	}
	if one == "" || one != two {
		t.Fatalf("fingerprint is not stable: %q vs %q", one, two)
	}
}

func TestSimpleEnrollWithTokenPostsESTRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/.well-known/est/ztna/simpleenroll" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token-1" {
			t.Fatalf("authorization = %q", got)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Fatalf("accept = %q", got)
		}
		if got := r.Header.Get("X-ZTNA-Enrollment-Nonce"); got != "nonce-1" {
			t.Fatalf("enrollment nonce = %q", got)
		}
		var req enrollmentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.DeviceID != "device-1" || req.Component != endpointComponent || req.Hostname != "host-1" {
			t.Fatalf("request = %+v", req)
		}
		if req.CSRPEM != "csr-pem" || req.PublicKeyFingerprint != "fingerprint-1" {
			t.Fatalf("csr/fingerprint = %q/%q", req.CSRPEM, req.PublicKeyFingerprint)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(enrollmentResponse{ID: "enroll-1", Status: "approved", CertPEM: "cert-pem", CAPEM: "ca-pem"})
	}))
	defer server.Close()

	result, err := SimpleEnrollWithToken(context.Background(), TokenEnrollmentConfig{
		CloudURL: server.URL,
		Token:    "token-1",
		Nonce:    "nonce-1",
		DeviceID: "device-1",
		Hostname: "host-1",
	}, []byte("csr-pem"), "fingerprint-1")
	if err != nil {
		t.Fatalf("SimpleEnrollWithToken returned error: %v", err)
	}
	if result.ID != "enroll-1" || string(result.CertPEM) != "cert-pem" || string(result.CAPEM) != "ca-pem" {
		t.Fatalf("result = %+v", result)
	}
}

func TestSimpleEnrollWithTokenRequiresBearerToken(t *testing.T) {
	_, err := SimpleEnrollWithToken(context.Background(), TokenEnrollmentConfig{CloudURL: "https://cloud.example", DeviceID: "device-1"}, []byte("csr"), "fingerprint")
	if err == nil {
		t.Fatalf("SimpleEnrollWithToken accepted missing token")
	}
}

func TestRenewCertWithMTLSPresentsClientCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	certPEM := testEndpointCertificatePEM(t, "device-1", key)
	csrPEM, err := CreateCSR(key, "device-1", "host-1")
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	fingerprint, err := PublicKeyFingerprint(&key.PublicKey)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}

	sawClientCert := false
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			t.Fatalf("renewal request did not present a client certificate")
		}
		sawClientCert = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(enrollmentResponse{ID: "renew-1", Status: "approved", CertPEM: "new-cert", CAPEM: "ca-cert"})
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()

	caFile := filepath.Join(t.TempDir(), "server-ca.pem")
	serverCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caFile, serverCAPEM, 0600); err != nil {
		t.Fatalf("write server CA: %v", err)
	}

	result, err := RenewCertWithMTLS(RenewalConfig{
		CloudURL:             server.URL,
		CAFile:               caFile,
		DeviceID:             "device-1",
		CSRPEM:               csrPEM,
		PublicKeyFingerprint: fingerprint,
		CertPEM:              certPEM,
		Signer:               key,
	})
	if err != nil {
		t.Fatalf("RenewCertWithMTLS returned error: %v", err)
	}
	if !sawClientCert {
		t.Fatalf("server did not observe a client certificate")
	}
	if result.ID != "renew-1" || string(result.CertPEM) != "new-cert" || string(result.CAPEM) != "ca-cert" {
		t.Fatalf("result = %+v", result)
	}
}

func testEndpointCertificatePEM(t *testing.T, commonName string, key *ecdsa.PrivateKey) []byte {
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
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
