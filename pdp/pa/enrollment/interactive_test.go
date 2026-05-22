package enrollment

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"testing"
)

func TestVerifyEnrollmentProofAcceptsECDSAP256(t *testing.T) {
	key := testEnrollmentKey(t)
	csr, _, err := ParseCSR(testEnrollmentCSRPEMWithKey(t, key, "device-1", "alice@example.com"))
	if err != nil {
		t.Fatalf("ParseCSR returned error: %v", err)
	}
	payload := []byte("proof payload")
	digest := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}

	if err := verifyEnrollmentProof(csr, payload, signature); err != nil {
		t.Fatalf("verifyEnrollmentProof returned error: %v", err)
	}
}

func TestVerifyEnrollmentProofRejectsRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	csr := testEnrollmentCSRWithSigner(t, key)
	payload := []byte("proof payload")
	digest := sha256.Sum256(payload)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}

	err = verifyEnrollmentProof(csr, payload, signature)
	if !errors.Is(err, ErrInvalidCSR) {
		t.Fatalf("verifyEnrollmentProof error = %v, want ErrInvalidCSR", err)
	}
}

func TestVerifyEnrollmentProofRejectsNonP256ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	csr := testEnrollmentCSRWithSigner(t, key)
	payload := []byte("proof payload")
	digest := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}

	err = verifyEnrollmentProof(csr, payload, signature)
	if !errors.Is(err, ErrInvalidCSR) {
		t.Fatalf("verifyEnrollmentProof error = %v, want ErrInvalidCSR", err)
	}
}

func testEnrollmentCSRWithSigner(t *testing.T, signer crypto.Signer) *x509.CertificateRequest {
	t.Helper()
	request := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "device-1"}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, request, signer)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	csr, _, err := ParseCSR(string(block))
	if err != nil {
		t.Fatalf("ParseCSR returned error: %v", err)
	}
	return csr
}
