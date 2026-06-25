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
	"math/big"
	"net/url"
	"testing"
	"time"

	"pdp/models"
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

func TestCleanExpiredInteractiveSessionsRemovesExpiredTransactions(t *testing.T) {
	dataStore := newEnrollmentTestStore(t)
	service := newEnrollmentTestService(t, dataStore)
	var expiredSessions []InteractiveSession
	service.SetInteractiveSessionExpiredHandler(func(session InteractiveSession, _ time.Time) {
		expiredSessions = append(expiredSessions, session)
	})

	active, err := service.StartInteractiveSession(InteractiveStartRequest{
		CSRHash:     "active-csr",
		SPKIHash:    "active-spki",
		DeviceNonce: "active-nonce",
		AuthURL:     "https://pdp.test",
	})
	if err != nil {
		t.Fatalf("StartInteractiveSession active returned error: %v", err)
	}
	expired, err := service.StartInteractiveSession(InteractiveStartRequest{
		CSRHash:     "expired-csr",
		SPKIHash:    "expired-spki",
		DeviceNonce: "expired-nonce",
		Hostname:    "expired-host",
		SourceIP:    "192.0.2.45",
		AuthURL:     "https://pdp.test",
	})
	if err != nil {
		t.Fatalf("StartInteractiveSession expired returned error: %v", err)
	}

	now := time.Now().UTC()
	expireInteractiveSessionForTest(t, service, expired.SessionID, now.Add(-time.Second))

	if removed := service.CleanExpiredInteractiveSessions(now); removed != 1 {
		t.Fatalf("CleanExpiredInteractiveSessions removed %d sessions, want 1", removed)
	}
	if service.HasInteractiveSession(expired.SessionID) {
		t.Fatalf("expired interactive enrollment session was not removed")
	}
	if !service.HasInteractiveSession(active.SessionID) {
		t.Fatalf("active interactive enrollment session was removed")
	}
	if len(expiredSessions) != 1 {
		t.Fatalf("expired handler called %d times, want 1", len(expiredSessions))
	}
	if expiredSessions[0].Hostname != "expired-host" || expiredSessions[0].SourceIP != "192.0.2.45" {
		t.Fatalf("unexpected expired session passed to handler: %#v", expiredSessions[0])
	}
}

func TestInteractiveSessionStatusDeletesExpiredTransaction(t *testing.T) {
	dataStore := newEnrollmentTestStore(t)
	service := newEnrollmentTestService(t, dataStore)

	session, err := service.StartInteractiveSession(InteractiveStartRequest{
		CSRHash:     "csr-hash",
		SPKIHash:    "spki-hash",
		DeviceNonce: "device-nonce",
		AuthURL:     "https://pdp.test",
	})
	if err != nil {
		t.Fatalf("StartInteractiveSession returned error: %v", err)
	}
	expireInteractiveSessionForTest(t, service, session.SessionID, time.Now().UTC().Add(-time.Second))

	status, err := service.InteractiveSessionStatus(session.SessionID, "device-nonce", session.PollSecret)
	if err != nil {
		t.Fatalf("InteractiveSessionStatus returned error: %v", err)
	}
	if status.Status != InteractiveStatusDenied || status.Reason != "enrollment_session_expired" {
		t.Fatalf("unexpected expired status: %#v", status)
	}
	if service.HasInteractiveSession(session.SessionID) {
		t.Fatalf("expired interactive enrollment session remained after status check")
	}
}

func TestExpireInteractiveSessionIfExpiredDeletesAndNotifies(t *testing.T) {
	dataStore := newEnrollmentTestStore(t)
	service := newEnrollmentTestService(t, dataStore)
	var expiredSessions []InteractiveSession
	service.SetInteractiveSessionExpiredHandler(func(session InteractiveSession, _ time.Time) {
		expiredSessions = append(expiredSessions, session)
	})

	session, err := service.StartInteractiveSession(InteractiveStartRequest{
		CSRHash:     "csr-hash",
		SPKIHash:    "spki-hash",
		DeviceNonce: "device-nonce",
		Hostname:    "expired-host",
		SourceIP:    "192.0.2.46",
		AuthURL:     "https://pdp.test",
	})
	if err != nil {
		t.Fatalf("StartInteractiveSession returned error: %v", err)
	}
	now := time.Now().UTC()
	expireInteractiveSessionForTest(t, service, session.SessionID, now.Add(-time.Second))

	if !service.ExpireInteractiveSessionIfExpired(session.SessionID, now) {
		t.Fatalf("ExpireInteractiveSessionIfExpired returned false")
	}
	if service.HasInteractiveSession(session.SessionID) {
		t.Fatalf("expired interactive enrollment session remained after explicit expiry")
	}
	if len(expiredSessions) != 1 {
		t.Fatalf("expired handler called %d times, want 1", len(expiredSessions))
	}
	if expiredSessions[0].Hostname != "expired-host" || expiredSessions[0].SourceIP != "192.0.2.46" {
		t.Fatalf("unexpected expired session passed to handler: %#v", expiredSessions[0])
	}
}

func TestCompleteInteractiveSessionDeletesInteractiveTransaction(t *testing.T) {
	dataStore := newEnrollmentTestStore(t)
	service := newEnrollmentTestService(t, dataStore)
	authority := newTestCertificateAuthority(t)
	service.SetInteractiveDeviceCertificateIssuer(authority.signCSRWithDeviceID)

	key := testEnrollmentKey(t)
	csrPEM := testEnrollmentCSRPEMWithKey(t, key, "pending-device", "alice@example.com")
	_, csrDER, err := ParseCSR(csrPEM)
	if err != nil {
		t.Fatalf("ParseCSR returned error: %v", err)
	}
	spkiHash, err := ComputeCSRFingerprint(csrPEM)
	if err != nil {
		t.Fatalf("ComputeCSRFingerprint returned error: %v", err)
	}

	start, err := service.StartInteractiveSession(InteractiveStartRequest{
		CSRHash:     hashBytes(csrDER),
		SPKIHash:    spkiHash,
		DeviceNonce: "device-nonce",
		AuthURL:     "https://pdp.test",
	})
	if err != nil {
		t.Fatalf("StartInteractiveSession returned error: %v", err)
	}
	organization := &models.Organization{ID: "organization-1", Enabled: true}
	idp := &models.IdentityProviderConfig{ID: "idp-1", Issuer: "https://idp.test", ClientID: "client-1", ClientSecret: "secret-1"}
	if _, err := service.BeginInteractiveIDPLogin(start.SessionID, organization, idp, "pkce", "nonce", "state"); err != nil {
		t.Fatalf("BeginInteractiveIDPLogin returned error: %v", err)
	}
	if _, err := service.CompleteInteractiveIDPLogin(start.SessionID, "subject-1", "alice@example.com", idp.Issuer, "user-1", "alice"); err != nil {
		t.Fatalf("CompleteInteractiveIDPLogin returned error: %v", err)
	}

	payload, err := canonicalEnrollmentProof(EnrollmentProofPayload{
		Type:                InteractiveProofType,
		EnrollmentSessionID: start.SessionID,
		DeviceNonce:         "device-nonce",
		DeviceChallenge:     start.DeviceChallenge,
		CSRHash:             hashBytes(csrDER),
		SPKIHash:            normalizeHex(spkiHash),
		PDPOrigin:           "https://pdp.test",
	})
	if err != nil {
		t.Fatalf("canonicalEnrollmentProof returned error: %v", err)
	}
	digest := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}

	result, err := service.CompleteInteractiveSession(InteractiveCompleteRequest{
		SessionID:      start.SessionID,
		DeviceNonce:    "device-nonce",
		PollSecret:     start.PollSecret,
		CSRPEM:         csrPEM,
		ProofPayload:   payload,
		ProofSignature: signature,
		PDPOrigin:      "https://pdp.test",
	})
	if err != nil {
		t.Fatalf("CompleteInteractiveSession returned error: %v", err)
	}
	if result.DeviceID == "" || result.CertificatePEM == "" {
		t.Fatalf("unexpected completion result: %#v", result)
	}
	if service.HasInteractiveSession(start.SessionID) {
		t.Fatalf("completed interactive enrollment session remained in runtime state")
	}
	if enrollment, found := dataStore.GetDeviceEnrollment(start.SessionID); !found || enrollment.DeviceID != result.DeviceID {
		t.Fatalf("completed enrollment was not persisted: found=%v enrollment=%#v", found, enrollment)
	}
}

func expireInteractiveSessionForTest(t *testing.T, service *Service, sessionID string, expiresAt time.Time) {
	t.Helper()
	session, ok := service.GetInteractiveSession(sessionID)
	if !ok {
		t.Fatalf("interactive session %s not found", sessionID)
	}
	session.ExpiresAt = expiresAt
	if err := service.saveInteractiveSession(session); err != nil {
		t.Fatalf("save expired interactive session: %v", err)
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

func (a *testCertificateAuthority) signCSRWithDeviceID(csrPEM []byte, validDays int, role, deviceID string) ([]byte, error) {
	a.roles = append(a.roles, role)
	csr, _, err := ParseCSR(string(csrPEM))
	if err != nil {
		return nil, err
	}
	deviceURI, err := url.Parse(DeviceIdentityURI(deviceID))
	if err != nil {
		return nil, err
	}
	a.serial++
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:   big.NewInt(a.serial),
		Subject:        pkix.Name{CommonName: deviceID},
		DNSNames:       csr.DNSNames,
		EmailAddresses: csr.EmailAddresses,
		URIs:           []*url.URL{deviceURI},
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
