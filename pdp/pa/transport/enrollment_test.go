package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"testing"

	paenrollment "pdp/pa/enrollment"
)

func TestNormalizeEnrollmentComponentUsesSingleEndpointIdentity(t *testing.T) {
	cases := map[string]string{
		"":         "endpoint",
		"device":   "endpoint",
		"endpoint": "endpoint",
		"tunnel":   "endpoint",
		"health":   "endpoint",
		"custom":   "custom",
	}
	for input, want := range cases {
		if got := paenrollment.NormalizeComponent(input); got != want {
			t.Fatalf("normalizeEnrollmentComponent(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestCanonicalCSRPEMAcceptsPEMAndBase64DER(t *testing.T) {
	csrDER := testCSRDER(t)
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))

	fromPEM, err := paenrollment.CanonicalCSRPEM(csrPEM)
	if err != nil {
		t.Fatalf("canonicalCSRPEM(PEM) returned error: %v", err)
	}
	fromBase64, err := paenrollment.CanonicalCSRPEM(base64.StdEncoding.EncodeToString(csrDER))
	if err != nil {
		t.Fatalf("canonicalCSRPEM(base64 DER) returned error: %v", err)
	}
	if fromPEM != fromBase64 {
		t.Fatalf("canonical CSR mismatch between PEM and base64 DER")
	}
}

func TestValidateCSREmailIdentityRequiresTokenUsername(t *testing.T) {
	csr := testCSRWithEmail(t, "user@example.com")
	if err := paenrollment.ValidateCSREmailIdentity(csr, "user@example.com"); err != nil {
		t.Fatalf("validateCSREmailIdentity returned error: %v", err)
	}
	if err := paenrollment.ValidateCSREmailIdentity(csr, "other@example.com"); err == nil {
		t.Fatalf("validateCSREmailIdentity accepted mismatched email")
	}
	if err := paenrollment.ValidateCSREmailIdentity(csr, "username"); err == nil {
		t.Fatalf("validateCSREmailIdentity accepted non-email username")
	}
}

func testCSRDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "device-1"},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return csrDER
}

func testCSRWithEmail(t *testing.T, email string) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: "device-1"},
		EmailAddresses: []string{email},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	return csr
}
