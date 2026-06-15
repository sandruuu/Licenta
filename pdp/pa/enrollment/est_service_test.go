package enrollment

import (
	"errors"
	"testing"
	"time"

	"pdp/models"
)

func TestServiceCompleteESTEnrollmentIssuesReusesAndRejectsReplay(t *testing.T) {
	dataStore := newEnrollmentTestStore(t)
	service := newEnrollmentTestService(t, dataStore)
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
	service := newEnrollmentTestService(t, dataStore)
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

func TestServiceCompleteESTEnrollmentAcceptsDeviceURISAN(t *testing.T) {
	dataStore := newEnrollmentTestStore(t)
	service := newEnrollmentTestService(t, dataStore)
	authority := newTestCertificateAuthority(t)
	service.SetCertificateAuthority(authority.signCSR, authority.revokeCertificate, func(component string) string {
		return "device-role"
	})

	deviceID := "2050b1864ca3647164fea13ac86d759e7f8bfb5ede15e202cc0869aa12671972"
	request := models.EnrollmentRequest{
		DeviceID:  deviceID,
		Component: "endpoint",
		CSRPEM:    testEnrollmentCSRPEMWithDeviceURI(t, testEnrollmentKey(t), "trustagent-device-2050b1864ca3647164fea13ac86d759e7f8bfb5ede15e202", deviceID, "alice@example.com"),
	}
	identity := ESTEnrollmentIdentity{
		DeviceID:       deviceID,
		UserID:         "user-1",
		Username:       "alice@example.com",
		TokenID:        "token-uri-san",
		TokenExpiresAt: time.Now().Add(5 * time.Minute),
	}

	issued, err := service.CompleteESTEnrollment(request, identity)
	if err != nil {
		t.Fatalf("CompleteESTEnrollment returned error: %v", err)
	}
	if issued.Enrollment.DeviceID != deviceID {
		t.Fatalf("enrollment device_id = %q, want %q", issued.Enrollment.DeviceID, deviceID)
	}
}

func TestServiceIssueEnrollmentTokenGeneratesNonceAndIncludesOptionalFields(t *testing.T) {
	dataStore := newEnrollmentTestStore(t)
	service := newEnrollmentTestService(t, dataStore)

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
	service := newEnrollmentTestService(t, dataStore)
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
