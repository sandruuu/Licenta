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
	"encoding/pem"
	"math/big"
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
	if csr.Subject.CommonName != "device-1" || len(csr.DNSNames) != 1 || csr.DNSNames[0] != "host-1" || len(csr.EmailAddresses) != 1 || csr.EmailAddresses[0] != "user@example.com" || len(csr.URIs) != 1 || csr.URIs[0].String() != "spiffe://agent/device/device-1" {
		t.Fatalf("CSR identity = subject=%+v dns=%v emails=%v uris=%v", csr.Subject, csr.DNSNames, csr.EmailAddresses, csr.URIs)
	}

	longDeviceID := "2050b1864ca3647164fea13ac86d759e7f8bfb5ede15e202cc0869aa12671972"
	longCSRPEM, err := CreateCSRWithIdentity(key, CSRIdentity{DeviceID: longDeviceID})
	if err != nil {
		t.Fatalf("CreateCSRWithIdentity long device returned error: %v", err)
	}
	block, _ = pem.Decode(longCSRPEM)
	if block == nil {
		t.Fatalf("long CSR was not PEM encoded")
	}
	longCSR, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificateRequest long returned error: %v", err)
	}
	if len(longCSR.Subject.CommonName) > 63 || !strings.HasPrefix(longCSR.Subject.CommonName, "ztna-device-") || len(longCSR.URIs) != 1 || longCSR.URIs[0].String() != "spiffe://agent/device/"+longDeviceID {
		t.Fatalf("long CSR identity = subject=%+v uris=%v", longCSR.Subject, longCSR.URIs)
	}
	if _, err := CreateCSRWithIdentity(key, CSRIdentity{DeviceID: "device-1", UserEmail: "User <user@example.com>"}); err == nil {
		t.Fatalf("CreateCSRWithIdentity accepted display-name email")
	}
}

func TestRunnerCreatesCSRCallsRemoteAndInstaller(t *testing.T) {
	key := newTestKey(t)
	remote := &fakeRemoteEnrollment{result: &RemoteCertificateResult{ID: "enroll-1", CertPEM: testCertificatePEM(t, "device-1"), CAPEM: testCertificatePEM(t, "ca")}}
	installer := &fakeCertificateInstaller{}
	runner, err := NewRunner(RunnerConfig{Hostname: "host-1", Remote: remote, KeyProvider: fakeKeyProvider{key: key}, Installer: installer})
	if err != nil {
		t.Fatalf("NewRunner returned error: %v", err)
	}
	result, err := runner.Enroll(context.Background(), RunnerInput{AccessToken: "access.jwt.token", Nonce: "nonce-1", DeviceID: "device-1", KeyName: "ZTNA_DeviceKey", KeyProvider: "Microsoft Platform Crypto Provider", UserEmail: "user@example.com"})
	if err != nil {
		t.Fatalf("Enroll returned error: %v", err)
	}
	if remote.enroll.AccessToken != "access.jwt.token" || remote.enroll.DeviceID != "device-1" || remote.enroll.Nonce != "nonce-1" || remote.enroll.KeyProof == "" {
		t.Fatalf("remote enroll = %+v", remote.enroll)
	}
	block, _ := pem.Decode(remote.enroll.CSRPEM)
	if block == nil {
		t.Fatalf("remote CSR was not PEM encoded")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificateRequest returned error: %v", err)
	}
	if csr.Subject.CommonName != "device-1" {
		t.Fatalf("CSR = %+v", csr.Subject)
	}
	if result.EnrollmentID != "enroll-1" || result.CertificateSHA256 == "" || result.CertificateNotAfter.IsZero() {
		t.Fatalf("result = %+v", result)
	}
	if !installer.called || installer.request.KeyName != "ZTNA_DeviceKey" || installer.request.KeyProvider != "Microsoft Platform Crypto Provider" {
		t.Fatalf("installer = %+v", installer)
	}
}

func TestRunnerRenewsThroughRemote(t *testing.T) {
	key := newTestKey(t)
	currentCertificate := testTLSCertificate(t, "device-1", key)
	remote := &fakeRemoteEnrollment{result: &RemoteCertificateResult{ID: "renew-1", CertPEM: testCertificatePEM(t, "device-1"), CAPEM: testCertificatePEM(t, "ca")}}
	installer := &fakeCertificateInstaller{}
	runner, err := NewRunner(RunnerConfig{Hostname: "host-1", Remote: remote, KeyProvider: fakeKeyProvider{key: key}, Installer: installer})
	if err != nil {
		t.Fatalf("NewRunner returned error: %v", err)
	}
	result, err := runner.Renew(context.Background(), RenewalInput{DeviceID: "device-1", KeyName: "ZTNA_DeviceKey", KeyProvider: "Microsoft Platform Crypto Provider", CurrentCertificate: currentCertificate})
	if err != nil {
		t.Fatalf("Renew returned error: %v", err)
	}
	if remote.renew.DeviceID != "device-1" || len(remote.renew.CurrentCertificate.Certificate) == 0 {
		t.Fatalf("remote renew = %+v", remote.renew)
	}
	if result.EnrollmentID != "renew-1" || !installer.called {
		t.Fatalf("result = %+v installer=%+v", result, installer)
	}
}

type fakeRemoteEnrollment struct {
	enroll RemoteEnrollInput
	renew  RemoteRenewalInput
	result *RemoteCertificateResult
}

func (remote *fakeRemoteEnrollment) EnrollDevice(_ context.Context, input RemoteEnrollInput) (*RemoteCertificateResult, error) {
	remote.enroll = input
	return remote.result, nil
}

func (remote *fakeRemoteEnrollment) RenewDeviceCertificate(_ context.Context, input RemoteRenewalInput) (*RemoteCertificateResult, error) {
	remote.renew = input
	return remote.result, nil
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
