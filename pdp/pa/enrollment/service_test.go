package enrollment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"pdp/models"
	"pdp/store"
)

func TestServiceIssueDeviceCertificateReusesSameKeyAndRevokesChangedKey(t *testing.T) {
	dataStore := newEnrollmentTestStore(t)
	service := NewService(dataStore)
	authority := newTestCertificateAuthority(t)
	service.SetCertificateAuthority(authority.signCSR, authority.revokeCertificate, func(component string) string {
		if component != "endpoint" {
			t.Fatalf("device role received component %q, want endpoint", component)
		}
		return "device-role"
	})

	request := models.EnrollmentRequest{
		DeviceID:  "device-1",
		Component: "tunnel",
		Hostname:  "host-1",
		CSRPEM:    testEnrollmentCSRPEM(t, "device-1", "alice@example.com"),
	}
	enrollment, certPEM, reused, err := service.IssueDeviceCertificate(request, "", "alice", "user-1", "alice@example.com")
	if err != nil {
		t.Fatalf("IssueDeviceCertificate returned error: %v", err)
	}
	if reused {
		t.Fatalf("first enrollment was marked reused")
	}
	if enrollment.Component != "endpoint" {
		t.Fatalf("component = %q, want endpoint", enrollment.Component)
	}
	if enrollment.Status != "approved" || enrollment.CertSerial == "" || string(certPEM) != enrollment.CertPEM {
		t.Fatalf("unexpected approved enrollment: %#v", enrollment)
	}
	if len(authority.roles) != 1 || authority.roles[0] != "device-role" {
		t.Fatalf("sign roles = %#v, want [device-role]", authority.roles)
	}

	reusedEnrollment, reusedCertPEM, reused, err := service.IssueDeviceCertificate(request, "", "alice", "user-1", "alice@example.com")
	if err != nil {
		t.Fatalf("IssueDeviceCertificate reuse returned error: %v", err)
	}
	if !reused || reusedEnrollment.ID != enrollment.ID || string(reusedCertPEM) != enrollment.CertPEM {
		t.Fatalf("same key was not reused")
	}
	if len(authority.roles) != 1 {
		t.Fatalf("same key triggered another certificate signing")
	}

	request.CSRPEM = testEnrollmentCSRPEM(t, "device-1", "alice@example.com")
	changedEnrollment, _, reused, err := service.IssueDeviceCertificate(request, "", "alice", "user-1", "alice@example.com")
	if err != nil {
		t.Fatalf("IssueDeviceCertificate changed key returned error: %v", err)
	}
	if reused || changedEnrollment.ID == enrollment.ID {
		t.Fatalf("changed key was not issued as a new enrollment")
	}
	if len(authority.roles) != 2 {
		t.Fatalf("changed key did not trigger a new certificate signing")
	}
	if len(authority.revokedSerials) != 1 || authority.revokedSerials[0] != enrollment.CertSerial {
		t.Fatalf("revoked serials = %#v, want [%s]", authority.revokedSerials, enrollment.CertSerial)
	}
}

func TestServiceSubmitPendingDeviceEnrollmentHandlesDuplicates(t *testing.T) {
	dataStore := newEnrollmentTestStore(t)
	service := NewService(dataStore)
	request := models.EnrollmentRequest{
		DeviceID:  "device-1",
		Component: "health",
		Hostname:  "host-1",
		CSRPEM:    testEnrollmentCSRPEM(t, "device-1", ""),
	}

	result, err := service.SubmitPendingDeviceEnrollment(request)
	if err != nil {
		t.Fatalf("SubmitPendingDeviceEnrollment returned error: %v", err)
	}
	if result.Action != PendingEnrollmentCreated || result.Enrollment.Status != "pending" || result.Enrollment.Component != "endpoint" {
		t.Fatalf("unexpected pending result: %#v", result)
	}
	if len(result.Enrollment.ID) != 64 {
		t.Fatalf("pending enrollment ID length = %d, want 64 hex chars", len(result.Enrollment.ID))
	}

	duplicate, err := service.SubmitPendingDeviceEnrollment(request)
	if err != nil {
		t.Fatalf("SubmitPendingDeviceEnrollment duplicate returned error: %v", err)
	}
	if duplicate.Action != PendingEnrollmentAlreadyPending || duplicate.Enrollment.ID != result.Enrollment.ID {
		t.Fatalf("same-key duplicate was not returned as already pending: %#v", duplicate)
	}

	request.CSRPEM = testEnrollmentCSRPEM(t, "device-1", "")
	_, err = service.SubmitPendingDeviceEnrollment(request)
	if !errors.Is(err, ErrPendingDifferentKey) {
		t.Fatalf("different-key duplicate error = %v, want ErrPendingDifferentKey", err)
	}
}

func TestServiceStartBrowserEnrollSessionRejectsSameKeyAndRevokesChangedKey(t *testing.T) {
	dataStore := newEnrollmentTestStore(t)
	service := NewService(dataStore)
	authority := newTestCertificateAuthority(t)
	service.SetCertificateAuthority(authority.signCSR, authority.revokeCertificate, func(component string) string {
		return "device-role"
	})

	deviceKey := testEnrollmentKey(t)
	enrollment, _, _, err := service.IssueDeviceCertificate(models.EnrollmentRequest{
		DeviceID:  "device-1",
		Component: "endpoint",
		Hostname:  "host-1",
		CSRPEM:    testEnrollmentCSRPEMWithKey(t, deviceKey, "device-1", "alice@example.com"),
	}, "", "alice", "user-1", "alice@example.com")
	if err != nil {
		t.Fatalf("IssueDeviceCertificate returned error: %v", err)
	}

	_, err = service.StartBrowserEnrollSession(models.EnrollmentRequest{
		DeviceID:  "device-1",
		Component: "endpoint",
		Hostname:  "host-1",
		CSRPEM:    testEnrollmentCSRPEMWithKey(t, deviceKey, "device-1", "alice@example.com"),
	})
	if !errors.Is(err, ErrAlreadyEnrolled) {
		t.Fatalf("same-key browser enrollment error = %v, want ErrAlreadyEnrolled", err)
	}

	session, err := service.StartBrowserEnrollSession(models.EnrollmentRequest{
		DeviceID:  "device-1",
		Component: "tunnel",
		Hostname:  "host-2",
		CSRPEM:    testEnrollmentCSRPEM(t, "device-1", "alice@example.com"),
	})
	if err != nil {
		t.Fatalf("StartBrowserEnrollSession changed key returned error: %v", err)
	}
	if session.Status != "pending" || session.Component != "endpoint" || session.Hostname != "host-2" || session.PublicKeyFingerprint == "" {
		t.Fatalf("unexpected browser enrollment session: %#v", session)
	}
	if len(authority.revokedSerials) != 1 || authority.revokedSerials[0] != enrollment.CertSerial {
		t.Fatalf("revoked serials = %#v, want [%s]", authority.revokedSerials, enrollment.CertSerial)
	}
	stored, found := dataStore.GetPendingEnroll(session.ID)
	if !found || stored.DeviceID != "device-1" {
		t.Fatalf("pending browser session was not stored: found=%v stored=%#v", found, stored)
	}
}

func TestServiceCompleteBrowserEnrollSessionUpdatesSession(t *testing.T) {
	dataStore := newEnrollmentTestStore(t)
	service := NewService(dataStore)
	authority := newTestCertificateAuthority(t)
	service.SetCertificateAuthority(authority.signCSR, authority.revokeCertificate, func(component string) string {
		if component != "endpoint" {
			t.Fatalf("device role received component %q, want endpoint", component)
		}
		return "device-role"
	})

	session, err := service.StartBrowserEnrollSession(models.EnrollmentRequest{
		DeviceID:  "device-1",
		Component: "tunnel",
		Hostname:  "host-1",
		CSRPEM:    testEnrollmentCSRPEM(t, "device-1", "alice@example.com"),
	})
	if err != nil {
		t.Fatalf("StartBrowserEnrollSession returned error: %v", err)
	}

	completion, err := service.CompleteBrowserEnrollSession(session.ID, "auth-token", "user-1", "alice@example.com", "ca-pem")
	if err != nil {
		t.Fatalf("CompleteBrowserEnrollSession returned error: %v", err)
	}
	if completion.Session.Status != "authenticated" || completion.Session.AuthToken != "auth-token" || completion.Session.CAPEM != "ca-pem" {
		t.Fatalf("unexpected completed session: %#v", completion.Session)
	}
	if completion.Enrollment.ID != session.ID || completion.Enrollment.UserID != "user-1" || completion.Enrollment.Username != "alice@example.com" || completion.Enrollment.ApprovedBy != "alice@example.com (OIDC)" {
		t.Fatalf("unexpected enrollment after session completion: %#v", completion.Enrollment)
	}
	if len(authority.roles) != 1 || authority.roles[0] != "device-role" {
		t.Fatalf("sign roles = %#v, want [device-role]", authority.roles)
	}
	storedSession, found := dataStore.GetPendingEnroll(session.ID)
	if !found || storedSession.Status != "authenticated" || storedSession.CertPEM == "" || storedSession.CertPEM != string(completion.CertPEM) {
		t.Fatalf("completed session was not persisted: found=%v stored=%#v", found, storedSession)
	}

	status, err := service.BrowserEnrollSessionStatus(session.ID)
	if err != nil {
		t.Fatalf("BrowserEnrollSessionStatus returned error: %v", err)
	}
	if status.Status != "authenticated" || status.CertPEM == "" || status.CAPEM != "ca-pem" || status.Message != "Device enrolled successfully" {
		t.Fatalf("unexpected browser session status: %#v", status)
	}
}

func TestServiceBrowserEnrollSessionDenyAndExpire(t *testing.T) {
	dataStore := newEnrollmentTestStore(t)
	service := NewService(dataStore)

	session, err := service.StartBrowserEnrollSession(models.EnrollmentRequest{
		DeviceID:  "device-1",
		Component: "endpoint",
		Hostname:  "host-1",
		CSRPEM:    testEnrollmentCSRPEM(t, "device-1", ""),
	})
	if err != nil {
		t.Fatalf("StartBrowserEnrollSession returned error: %v", err)
	}
	denied, err := service.DenyBrowserEnrollSession(session.ID)
	if err != nil {
		t.Fatalf("DenyBrowserEnrollSession returned error: %v", err)
	}
	if denied.Status != "denied" {
		t.Fatalf("denied status = %q, want denied", denied.Status)
	}
	status, err := service.BrowserEnrollSessionStatus(session.ID)
	if err != nil {
		t.Fatalf("BrowserEnrollSessionStatus denied returned error: %v", err)
	}
	if status.Status != "denied" || status.Message != "Authentication failed" {
		t.Fatalf("unexpected denied status response: %#v", status)
	}

	expired := &models.PendingEnrollSession{
		ID:        "expired-session",
		Status:    "pending",
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	dataStore.SavePendingEnroll(expired)
	_, err = service.ActiveBrowserEnrollSession(expired.ID)
	if !errors.Is(err, ErrExpiredSession) {
		t.Fatalf("ActiveBrowserEnrollSession expired error = %v, want ErrExpiredSession", err)
	}
	if _, found := dataStore.GetPendingEnroll(expired.ID); found {
		t.Fatalf("expired pending enrollment session was not deleted")
	}

	_, err = service.BrowserEnrollSessionStatus("missing-session")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("BrowserEnrollSessionStatus missing error = %v, want ErrNotFound", err)
	}
}

func TestServiceAdminApproveAndRevokeEnrollment(t *testing.T) {
	dataStore := newEnrollmentTestStore(t)
	service := NewService(dataStore)
	authority := newTestCertificateAuthority(t)
	service.SetCertificateAuthority(authority.signCSR, authority.revokeCertificate, func(component string) string {
		if component != "endpoint" {
			t.Fatalf("device role received component %q, want endpoint", component)
		}
		return "device-role"
	})

	pending, err := service.SubmitPendingDeviceEnrollment(models.EnrollmentRequest{
		DeviceID:  "device-1",
		Component: "tunnel",
		Hostname:  "host-1",
		CSRPEM:    testEnrollmentCSRPEM(t, "device-1", ""),
	})
	if err != nil {
		t.Fatalf("SubmitPendingDeviceEnrollment returned error: %v", err)
	}

	approved, certPEM, err := service.ApprovePendingEnrollment(pending.Enrollment.ID, "admin@example.com")
	if err != nil {
		t.Fatalf("ApprovePendingEnrollment returned error: %v", err)
	}
	if approved.Status != "approved" || approved.ApprovedBy != "admin@example.com" || approved.CertSerial == "" || string(certPEM) != approved.CertPEM {
		t.Fatalf("unexpected approved enrollment: %#v", approved)
	}
	if len(authority.roles) != 1 || authority.roles[0] != "device-role" {
		t.Fatalf("sign roles = %#v, want [device-role]", authority.roles)
	}
	stored, found := dataStore.GetDeviceEnrollment(approved.ID)
	if !found || stored.Status != "approved" || stored.CertSerial != approved.CertSerial {
		t.Fatalf("approved enrollment was not persisted: found=%v stored=%#v", found, stored)
	}

	_, _, err = service.ApprovePendingEnrollment(approved.ID, "admin@example.com")
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("ApprovePendingEnrollment non-pending error = %v, want ErrInvalidState", err)
	}

	revoked, err := service.RevokeDeviceEnrollment(approved.ID)
	if err != nil {
		t.Fatalf("RevokeDeviceEnrollment returned error: %v", err)
	}
	if revoked.Status != "revoked" {
		t.Fatalf("revoked status = %q, want revoked", revoked.Status)
	}
	if len(authority.revokedSerials) != 1 || authority.revokedSerials[0] != approved.CertSerial {
		t.Fatalf("revoked serials = %#v, want [%s]", authority.revokedSerials, approved.CertSerial)
	}
}

func TestServiceDeviceEnrollmentStatusAndList(t *testing.T) {
	dataStore := newEnrollmentTestStore(t)
	service := NewService(dataStore)
	authority := newTestCertificateAuthority(t)
	service.SetCertificateAuthority(authority.signCSR, authority.revokeCertificate, func(component string) string {
		return "device-role"
	})

	pending, err := service.SubmitPendingDeviceEnrollment(models.EnrollmentRequest{
		DeviceID:  "device-1",
		Component: "endpoint",
		Hostname:  "host-1",
		CSRPEM:    testEnrollmentCSRPEM(t, "device-1", ""),
	})
	if err != nil {
		t.Fatalf("SubmitPendingDeviceEnrollment pending returned error: %v", err)
	}
	pendingStatus, err := service.DeviceEnrollmentStatus(pending.Enrollment.ID)
	if err != nil {
		t.Fatalf("DeviceEnrollmentStatus pending returned error: %v", err)
	}
	if pendingStatus.Status != "pending" || pendingStatus.Message != "Awaiting admin approval" || pendingStatus.CertPEM != "" {
		t.Fatalf("unexpected pending status: %#v", pendingStatus)
	}

	approvedPending, err := service.SubmitPendingDeviceEnrollment(models.EnrollmentRequest{
		DeviceID:  "device-2",
		Component: "endpoint",
		Hostname:  "host-2",
		CSRPEM:    testEnrollmentCSRPEM(t, "device-2", ""),
	})
	if err != nil {
		t.Fatalf("SubmitPendingDeviceEnrollment approved fixture returned error: %v", err)
	}
	approved, _, err := service.ApprovePendingEnrollment(approvedPending.Enrollment.ID, "admin@example.com")
	if err != nil {
		t.Fatalf("ApprovePendingEnrollment returned error: %v", err)
	}
	approvedStatus, err := service.DeviceEnrollmentStatus(approved.ID)
	if err != nil {
		t.Fatalf("DeviceEnrollmentStatus approved returned error: %v", err)
	}
	if approvedStatus.Status != "approved" || approvedStatus.Message != "Certificate issued" || approvedStatus.CertPEM == "" || approvedStatus.CAPEM != "" {
		t.Fatalf("unexpected approved status: %#v", approvedStatus)
	}

	listed, err := service.ListDeviceEnrollments()
	if err != nil {
		t.Fatalf("ListDeviceEnrollments returned error: %v", err)
	}
	listedByID := map[string]bool{}
	for _, enrollment := range listed {
		listedByID[enrollment.ID] = true
	}
	if !listedByID[pending.Enrollment.ID] || !listedByID[approved.ID] {
		t.Fatalf("expected enrollments missing from list: %#v", listedByID)
	}

	if _, err := service.RevokeDeviceEnrollment(approved.ID); err != nil {
		t.Fatalf("RevokeDeviceEnrollment returned error: %v", err)
	}
	revokedStatus, err := service.DeviceEnrollmentStatus(approved.ID)
	if err != nil {
		t.Fatalf("DeviceEnrollmentStatus revoked returned error: %v", err)
	}
	if revokedStatus.Status != "revoked" || revokedStatus.Message != "Enrollment has been revoked" {
		t.Fatalf("unexpected revoked status: %#v", revokedStatus)
	}

	_, err = service.DeviceEnrollmentStatus(" ")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("DeviceEnrollmentStatus empty error = %v, want ErrInvalidRequest", err)
	}
	_, err = service.DeviceEnrollmentStatus("missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeviceEnrollmentStatus missing error = %v, want ErrNotFound", err)
	}
}

func TestServiceCompleteESTEnrollmentIssuesReusesAndRejectsReplay(t *testing.T) {
	dataStore := newEnrollmentTestStore(t)
	service := NewService(dataStore)
	authority := newTestCertificateAuthority(t)
	service.SetCertificateAuthority(authority.signCSR, authority.revokeCertificate, func(component string) string {
		if component != "endpoint" {
			t.Fatalf("device role received component %q, want endpoint", component)
		}
		return "device-role"
	})

	request := models.EnrollmentRequest{
		Component: "tunnel",
		Hostname:  "host-1",
		CSRPEM:    testEnrollmentCSRPEM(t, "device-1", "alice@example.com"),
	}
	identity := ESTEnrollmentIdentity{
		DeviceID:       "device-1",
		UserID:         "user-1",
		Username:       "alice@example.com",
		TokenID:        "token-1",
		TokenExpiresAt: time.Now().Add(5 * time.Minute),
	}
	issued, err := service.CompleteESTEnrollment(request, identity)
	if err != nil {
		t.Fatalf("CompleteESTEnrollment returned error: %v", err)
	}
	if issued.Reused || issued.Enrollment.DeviceID != "device-1" || issued.Enrollment.Component != "endpoint" || issued.Enrollment.ApprovedBy != "alice@example.com (EST)" || issued.Enrollment.UserID != "user-1" {
		t.Fatalf("unexpected EST enrollment: %#v", issued.Enrollment)
	}
	if len(authority.roles) != 1 || authority.roles[0] != "device-role" {
		t.Fatalf("sign roles = %#v, want [device-role]", authority.roles)
	}

	identity.TokenID = "token-2"
	reused, err := service.CompleteESTEnrollment(request, identity)
	if err != nil {
		t.Fatalf("CompleteESTEnrollment reuse returned error: %v", err)
	}
	if !reused.Reused || reused.Enrollment.ID != issued.Enrollment.ID || string(reused.CertPEM) != issued.Enrollment.CertPEM {
		t.Fatalf("same-key EST enrollment was not reused: %#v", reused)
	}
	if len(authority.roles) != 1 {
		t.Fatalf("same-key EST reuse triggered another certificate signing")
	}

	_, err = service.CompleteESTEnrollment(request, identity)
	if !errors.Is(err, ErrTokenAlreadyUsed) {
		t.Fatalf("CompleteESTEnrollment replay error = %v, want ErrTokenAlreadyUsed", err)
	}
}

func TestServiceCompleteESTEnrollmentValidatesTokenAndCSRBinding(t *testing.T) {
	dataStore := newEnrollmentTestStore(t)
	service := NewService(dataStore)
	authority := newTestCertificateAuthority(t)
	service.SetCertificateAuthority(authority.signCSR, authority.revokeCertificate, func(component string) string {
		return "device-role"
	})

	validRequest := models.EnrollmentRequest{
		DeviceID:  "device-1",
		Component: "endpoint",
		CSRPEM:    testEnrollmentCSRPEM(t, "device-1", "alice@example.com"),
	}
	validIdentity := ESTEnrollmentIdentity{
		DeviceID:       "device-1",
		UserID:         "user-1",
		Username:       "alice@example.com",
		TokenID:        "token-valid",
		TokenExpiresAt: time.Now().Add(5 * time.Minute),
	}

	_, err := service.CompleteESTEnrollment(validRequest, ESTEnrollmentIdentity{
		UserID:         "user-1",
		Username:       "alice@example.com",
		TokenID:        "token-missing-device",
		TokenExpiresAt: time.Now().Add(5 * time.Minute),
	})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("missing token device error = %v, want ErrForbidden", err)
	}

	mismatchIdentity := validIdentity
	mismatchIdentity.DeviceID = "device-2"
	mismatchIdentity.TokenID = "token-mismatch"
	_, err = service.CompleteESTEnrollment(validRequest, mismatchIdentity)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("mismatched token device error = %v, want ErrForbidden", err)
	}

	cnMismatchRequest := validRequest
	cnMismatchRequest.CSRPEM = testEnrollmentCSRPEM(t, "other-device", "alice@example.com")
	cnMismatchIdentity := validIdentity
	cnMismatchIdentity.TokenID = "token-cn-mismatch"
	_, err = service.CompleteESTEnrollment(cnMismatchRequest, cnMismatchIdentity)
	if !errors.Is(err, ErrInvalidCSR) {
		t.Fatalf("CSR CN mismatch error = %v, want ErrInvalidCSR", err)
	}

	emailMismatchRequest := validRequest
	emailMismatchRequest.CSRPEM = testEnrollmentCSRPEM(t, "device-1", "mallory@example.com")
	emailMismatchIdentity := validIdentity
	emailMismatchIdentity.TokenID = "token-email-mismatch"
	_, err = service.CompleteESTEnrollment(emailMismatchRequest, emailMismatchIdentity)
	if !errors.Is(err, ErrInvalidCSR) {
		t.Fatalf("CSR email mismatch error = %v, want ErrInvalidCSR", err)
	}

	invalidTokenIdentity := validIdentity
	invalidTokenIdentity.TokenID = ""
	_, err = service.CompleteESTEnrollment(validRequest, invalidTokenIdentity)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("invalid token error = %v, want ErrInvalidToken", err)
	}
	if len(authority.roles) != 0 {
		t.Fatalf("validation failures triggered certificate signing: roles=%#v", authority.roles)
	}
}

func TestServiceIssueEnrollmentTokenGeneratesNonceAndIncludesOptionalFields(t *testing.T) {
	dataStore := newEnrollmentTestStore(t)
	service := NewService(dataStore)

	var issuedForDevice string
	var issuedNonce string
	var issuedUserSID string
	service.SetEnrollmentTokenIssuer(func(userID, username, role, deviceID, nonce, userSID string) (string, time.Duration, error) {
		if userID != "user-1" || username != "alice@example.com" || role != "user" {
			t.Fatalf("unexpected token subject: userID=%q username=%q role=%q", userID, username, role)
		}
		issuedForDevice = deviceID
		issuedNonce = nonce
		issuedUserSID = userSID
		return "enrollment-token", 5 * time.Minute, nil
	})

	issued, err := service.IssueEnrollmentToken(EnrollmentTokenParent{
		TokenID:  "parent-token",
		UserID:   "user-1",
		Username: "alice@example.com",
		Role:     "user",
		DeviceID: "device-1",
	}, EnrollmentTokenIssueRequest{
		DeviceID: "device-1",
		UserSID:  "S-1-5-21-1000",
	})
	if err != nil {
		t.Fatalf("IssueEnrollmentToken returned error: %v", err)
	}
	if issued.EnrollmentToken != "enrollment-token" || issued.TokenType != "Bearer" || issued.ExpiresIn != 300 || issued.DeviceID != "device-1" || issued.UserEmail != "alice@example.com" || issued.UserSID != "S-1-5-21-1000" {
		t.Fatalf("unexpected issued token response: %#v", issued)
	}
	if issuedForDevice != "device-1" || issuedUserSID != "S-1-5-21-1000" || issuedNonce != issued.Nonce || len(issued.Nonce) != 32 {
		t.Fatalf("issuer received device=%q nonce=%q sid=%q, response nonce=%q", issuedForDevice, issuedNonce, issuedUserSID, issued.Nonce)
	}
}

func TestServiceIssueEnrollmentTokenValidatesParentTokenAndDeviceBinding(t *testing.T) {
	dataStore := newEnrollmentTestStore(t)
	service := NewService(dataStore)
	issuerCalls := 0
	service.SetEnrollmentTokenIssuer(func(userID, username, role, deviceID, nonce, userSID string) (string, time.Duration, error) {
		issuerCalls++
		return "", 0, errors.New("issuer unavailable")
	})

	validParent := EnrollmentTokenParent{
		TokenID:  "parent-token",
		UserID:   "user-1",
		Username: "alice@example.com",
		Role:     "user",
		DeviceID: "device-1",
	}

	invalidPurpose := validParent
	invalidPurpose.Purpose = "device_enrollment"
	_, err := service.IssueEnrollmentToken(invalidPurpose, EnrollmentTokenIssueRequest{})
	if !errors.Is(err, ErrInvalidParentToken) {
		t.Fatalf("invalid purpose error = %v, want ErrInvalidParentToken", err)
	}

	if !dataStore.ConsumeTokenOnce("revoked-parent", time.Now().Add(5*time.Minute)) {
		t.Fatalf("failed to mark parent token revoked")
	}
	revokedParent := validParent
	revokedParent.TokenID = "revoked-parent"
	_, err = service.IssueEnrollmentToken(revokedParent, EnrollmentTokenIssueRequest{})
	if !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("revoked parent error = %v, want ErrTokenRevoked", err)
	}

	missingDevice := validParent
	missingDevice.DeviceID = ""
	_, err = service.IssueEnrollmentToken(missingDevice, EnrollmentTokenIssueRequest{})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("missing parent device error = %v, want ErrForbidden", err)
	}

	_, err = service.IssueEnrollmentToken(validParent, EnrollmentTokenIssueRequest{DeviceID: "device-2"})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("requested device mismatch error = %v, want ErrForbidden", err)
	}

	_, err = service.IssueEnrollmentToken(validParent, EnrollmentTokenIssueRequest{Nonce: "nonce-1"})
	if !errors.Is(err, ErrTokenIssue) {
		t.Fatalf("issuer failure error = %v, want ErrTokenIssue", err)
	}
	if issuerCalls != 1 {
		t.Fatalf("issuer calls = %d, want 1", issuerCalls)
	}
}

func TestServiceRenewDeviceCertificateUpdatesCertificateAndRejectsKeyMismatch(t *testing.T) {
	dataStore := newEnrollmentTestStore(t)
	service := NewService(dataStore)
	authority := newTestCertificateAuthority(t)
	service.SetCertificateAuthority(authority.signCSR, authority.revokeCertificate, func(component string) string {
		return "device-role"
	})

	deviceKey := testEnrollmentKey(t)
	enrollment, _, _, err := service.IssueDeviceCertificate(models.EnrollmentRequest{
		DeviceID:  "device-1",
		Component: "endpoint",
		Hostname:  "host-1",
		CSRPEM:    testEnrollmentCSRPEMWithKey(t, deviceKey, "device-1", "alice@example.com"),
	}, "", "alice", "user-1", "alice@example.com")
	if err != nil {
		t.Fatalf("IssueDeviceCertificate returned error: %v", err)
	}
	oldSerial := enrollment.CertSerial

	renewed, certPEM, err := service.RenewDeviceCertificate(models.EnrollmentRequest{
		DeviceID:  "device-1",
		Component: "endpoint",
		CSRPEM:    testEnrollmentCSRPEMWithKey(t, deviceKey, "device-1", "alice@example.com"),
	}, enrollment)
	if err != nil {
		t.Fatalf("RenewDeviceCertificate returned error: %v", err)
	}
	if renewed.ID != enrollment.ID || renewed.CertSerial == "" || renewed.CertSerial == oldSerial || string(certPEM) != renewed.CertPEM {
		t.Fatalf("unexpected renewed enrollment: %#v", renewed)
	}
	if len(authority.revokedSerials) != 1 || authority.revokedSerials[0] != oldSerial {
		t.Fatalf("revoked serials = %#v, want [%s]", authority.revokedSerials, oldSerial)
	}
	stored, found := dataStore.GetDeviceEnrollmentByComponent("device-1", "endpoint")
	if !found || stored.CertSerial != renewed.CertSerial {
		t.Fatalf("renewed enrollment was not persisted: found=%v stored=%#v", found, stored)
	}

	_, _, err = service.RenewDeviceCertificate(models.EnrollmentRequest{
		DeviceID:  "device-1",
		Component: "endpoint",
		CSRPEM:    testEnrollmentCSRPEM(t, "device-1", "alice@example.com"),
	}, renewed)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("RenewDeviceCertificate mismatched key error = %v, want ErrForbidden", err)
	}
	if len(authority.revokedSerials) != 1 || len(authority.roles) != 2 {
		t.Fatalf("mismatched key changed signing/revocation state: roles=%#v revoked=%#v", authority.roles, authority.revokedSerials)
	}
}

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
