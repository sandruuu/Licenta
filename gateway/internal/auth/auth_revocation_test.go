package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestParseVaultRevokedSerialsFromPEMAndDER(t *testing.T) {
	pemCRL, derCRL, expected := buildTestCRL(t)

	gotFromPEM, err := parseVaultRevokedSerials(pemCRL)
	if err != nil {
		t.Fatalf("parse PEM CRL: %v", err)
	}
	assertSameSerials(t, gotFromPEM, expected)

	gotFromDER, err := parseVaultRevokedSerials(derCRL)
	if err != nil {
		t.Fatalf("parse DER CRL: %v", err)
	}
	assertSameSerials(t, gotFromDER, expected)
}

func TestExtractCRLDERRejectsInvalidPayload(t *testing.T) {
	if _, err := extractCRLDER([]byte("not-a-crl")); err == nil {
		t.Fatal("expected error for invalid CRL payload")
	}
}

func buildTestCRL(t *testing.T) ([]byte, []byte, []string) {
	t.Helper()

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}

	now := time.Now()
	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("create issuer cert: %v", err)
	}

	issuerCert, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatalf("parse issuer cert: %v", err)
	}

	revoked := []x509.RevocationListEntry{
		{SerialNumber: big.NewInt(12345), RevocationTime: now.Add(-2 * time.Minute)},
		{SerialNumber: big.NewInt(67890), RevocationTime: now.Add(-1 * time.Minute)},
	}

	crlTemplate := &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                now.Add(-5 * time.Minute),
		NextUpdate:                now.Add(55 * time.Minute),
		RevokedCertificateEntries: revoked,
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, issuerCert, issuerKey)
	if err != nil {
		t.Fatalf("create revocation list: %v", err)
	}

	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
	return crlPEM, crlDER, []string{"12345", "67890"}
}

func assertSameSerials(t *testing.T, got, expected []string) {
	t.Helper()

	if len(got) != len(expected) {
		t.Fatalf("unexpected serial count: got=%d expected=%d (got=%v)", len(got), len(expected), got)
	}

	expectedSet := make(map[string]struct{}, len(expected))
	for _, serial := range expected {
		expectedSet[serial] = struct{}{}
	}

	for _, serial := range got {
		if _, ok := expectedSet[serial]; !ok {
			t.Fatalf("unexpected serial %s in result %v", serial, got)
		}
	}
}
