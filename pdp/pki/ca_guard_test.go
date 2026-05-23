package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnsureCAPEMCompatibleAllowsMissingOrSameCA(t *testing.T) {
	caPEM := testCAPEM(t, "TrustCloud CA")
	path := filepath.Join(t.TempDir(), "ca.pem")

	if err := EnsureCAPEMCompatible(path, caPEM); err != nil {
		t.Fatalf("missing CA path should be allowed: %v", err)
	}
	if err := os.WriteFile(path, caPEM, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	if err := EnsureCAPEMCompatible(path, caPEM); err != nil {
		t.Fatalf("same CA should be allowed: %v", err)
	}
}

func TestEnsureCAPEMCompatibleRejectsChangedCA(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, testCAPEM(t, "TrustCloud CA 1"), 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}

	if err := EnsureCAPEMCompatible(path, testCAPEM(t, "TrustCloud CA 2")); err == nil {
		t.Fatalf("changed CA should be rejected")
	}
}

func testCAPEM(t *testing.T, commonName string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
