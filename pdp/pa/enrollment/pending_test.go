package enrollment

import (
	"errors"
	"testing"
	"time"

	"pdp/internal/testredis"
	"pdp/models"
)

func TestServiceSubmitPendingDeviceEnrollmentHandlesDuplicates(t *testing.T) {
	dataStore := newEnrollmentTestStore(t)
	service := NewService(dataStore, testredis.NewClient(t))
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
	service := NewService(dataStore, testredis.NewClient(t))
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
	stored, found := service.getPendingEnroll(session.ID)
	if !found || stored.DeviceID != "device-1" {
		t.Fatalf("pending browser session was not stored: found=%v stored=%#v", found, stored)
	}
}

func TestServiceCompleteBrowserEnrollSessionUpdatesSession(t *testing.T) {
	dataStore := newEnrollmentTestStore(t)
	service := NewService(dataStore, testredis.NewClient(t))
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
	storedSession, found := service.getPendingEnroll(session.ID)
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
	service := NewService(dataStore, testredis.NewClient(t))

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
	if err := service.savePendingEnroll(expired); err != nil {
		t.Fatalf("save expired pending enroll: %v", err)
	}
	_, err = service.ActiveBrowserEnrollSession(expired.ID)
	if !errors.Is(err, ErrExpiredSession) {
		t.Fatalf("ActiveBrowserEnrollSession expired error = %v, want ErrExpiredSession", err)
	}
	if _, found := service.getPendingEnroll(expired.ID); found {
		t.Fatalf("expired pending enrollment session was not deleted")
	}

	_, err = service.BrowserEnrollSessionStatus("missing-session")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("BrowserEnrollSessionStatus missing error = %v, want ErrNotFound", err)
	}
}

func TestServiceAdminApproveAndRevokeEnrollment(t *testing.T) {
	dataStore := newEnrollmentTestStore(t)
	service := NewService(dataStore, testredis.NewClient(t))
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
	service := NewService(dataStore, testredis.NewClient(t))
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
