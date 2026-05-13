package enrollment

import (
	"fmt"
	"log"
	"strings"
	"time"

	"pdp/models"
	"pdp/util"
)

func (s *Service) SubmitPendingDeviceEnrollment(req models.EnrollmentRequest) (*PendingEnrollmentResult, error) {
	prepared, err := s.prepareEnrollmentRequest(req)
	if err != nil {
		return nil, err
	}

	if existing, found := s.store.GetDeviceEnrollmentByComponent(prepared.deviceID, prepared.component); found {
		if existing.Status == "pending" {
			if existing.PublicKeyFingerprint != "" && prepared.csrFingerprint != "" && existing.PublicKeyFingerprint != prepared.csrFingerprint {
				log.Printf("[ENROLL] Rejected duplicate enrollment with different key: device=%s component=%s", prepared.deviceID, prepared.component)
				return nil, ErrPendingDifferentKey
			}
			return &PendingEnrollmentResult{Enrollment: existing, Action: PendingEnrollmentAlreadyPending}, nil
		}
		if existing.Status == "approved" && existing.ExpiresAt.After(time.Now()) {
			if existing.PublicKeyFingerprint == prepared.csrFingerprint {
				return &PendingEnrollmentResult{Enrollment: existing, Action: PendingEnrollmentAlreadyApproved}, nil
			}
			s.revokeChangedKeyEnrollment(existing, prepared.csrFingerprint)
		}
	}

	enrollmentID, err := generateEnrollmentSecretID()
	if err != nil {
		return nil, fmt.Errorf("generate enrollment ID: %w", err)
	}
	enrollment := &models.DeviceEnrollment{
		ID:                   enrollmentID,
		DeviceID:             prepared.deviceID,
		Component:            prepared.component,
		Hostname:             prepared.hostname,
		PublicKeyFingerprint: prepared.csrFingerprint,
		Status:               "pending",
		CSRPEM:               prepared.csrPEM,
		EnrolledAt:           time.Now(),
	}
	s.store.SaveDeviceEnrollment(enrollment)

	log.Printf("[ENROLL] New enrollment request: id=%s device=%s component=%s hostname=%s fingerprint=%s",
		enrollmentID, prepared.deviceID, prepared.component, prepared.hostname, prepared.csrFingerprint)

	return &PendingEnrollmentResult{Enrollment: enrollment, Action: PendingEnrollmentCreated}, nil
}

func (s *Service) StartBrowserEnrollSession(req models.EnrollmentRequest) (*models.PendingEnrollSession, error) {
	prepared, err := s.prepareEnrollmentRequest(req)
	if err != nil {
		return nil, err
	}

	if existing, found := s.store.GetDeviceEnrollmentByComponent(prepared.deviceID, prepared.component); found {
		if existing.Status == "approved" && existing.ExpiresAt.After(time.Now()) {
			if existing.PublicKeyFingerprint == prepared.csrFingerprint {
				return nil, ErrAlreadyEnrolled
			}
			s.revokeChangedKeyEnrollment(existing, prepared.csrFingerprint)
		}
	}

	sessionID, err := util.GenerateID("enroll")
	if err != nil {
		return nil, fmt.Errorf("generate enrollment session ID: %w", err)
	}
	session := &models.PendingEnrollSession{
		ID:                   sessionID,
		DeviceID:             prepared.deviceID,
		Component:            prepared.component,
		Hostname:             prepared.hostname,
		CSRPEM:               prepared.csrPEM,
		PublicKeyFingerprint: prepared.csrFingerprint,
		Status:               "pending",
		CreatedAt:            time.Now(),
		ExpiresAt:            time.Now().Add(s.activeBrowserSessionTTL()),
	}
	s.store.SavePendingEnroll(session)

	log.Printf("[ENROLL] Browser enrollment session created: %s (device=%s, host=%s)", sessionID, prepared.deviceID, prepared.hostname)

	return session, nil
}

func (s *Service) ActiveBrowserEnrollSession(sessionID string) (*models.PendingEnrollSession, error) {
	if s == nil || s.store == nil {
		return nil, fmt.Errorf("enrollment store not initialized")
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return nil, fmt.Errorf("%w: session ID is required", ErrInvalidRequest)
	}
	session, found := s.store.GetPendingEnroll(sessionID)
	if !found {
		return nil, ErrNotFound
	}
	if session.ExpiresAt.Before(time.Now()) {
		s.store.DeletePendingEnroll(sessionID)
		return nil, ErrExpiredSession
	}
	return session, nil
}

func (s *Service) DenyBrowserEnrollSession(sessionID string) (*models.PendingEnrollSession, error) {
	session, err := s.ActiveBrowserEnrollSession(sessionID)
	if err != nil {
		return nil, err
	}
	session.Status = "denied"
	s.store.SavePendingEnroll(session)
	return session, nil
}

func (s *Service) CompleteBrowserEnrollSession(sessionID, authToken, userID, username, caPEM string) (*BrowserEnrollSessionCompletion, error) {
	session, err := s.ActiveBrowserEnrollSession(sessionID)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(username) == "" {
		return nil, fmt.Errorf("%w: user identity is required", ErrInvalidRequest)
	}

	enrollment, certPEM, reused, err := s.IssueDeviceCertificate(models.EnrollmentRequest{
		DeviceID:             session.DeviceID,
		Component:            session.Component,
		Hostname:             session.Hostname,
		CSRPEM:               session.CSRPEM,
		PublicKeyFingerprint: session.PublicKeyFingerprint,
	}, session.ID, username+" (OIDC)", userID, username)
	if err != nil {
		return nil, err
	}

	session.Status = "authenticated"
	session.AuthToken = authToken
	session.UserID = userID
	session.Username = username
	session.CertPEM = string(certPEM)
	if strings.TrimSpace(caPEM) != "" {
		session.CAPEM = caPEM
	}
	s.store.SavePendingEnroll(session)

	return &BrowserEnrollSessionCompletion{
		Session:    session,
		Enrollment: enrollment,
		CertPEM:    certPEM,
		Reused:     reused,
	}, nil
}

func (s *Service) BrowserEnrollSessionStatus(sessionID string) (*BrowserEnrollSessionStatus, error) {
	if s == nil || s.store == nil {
		return nil, fmt.Errorf("enrollment store not initialized")
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return nil, fmt.Errorf("%w: session ID is required", ErrInvalidRequest)
	}
	session, found := s.store.GetPendingEnroll(sessionID)
	if !found {
		return nil, ErrNotFound
	}

	status := &BrowserEnrollSessionStatus{Status: session.Status}
	switch session.Status {
	case "authenticated":
		status.CertPEM = session.CertPEM
		status.CAPEM = session.CAPEM
		status.Message = "Device enrolled successfully"
	case "pending":
		status.Message = "Waiting for user authentication"
	case "denied":
		status.Message = "Authentication failed"
	}
	return status, nil
}

func (s *Service) DeviceEnrollmentStatus(enrollmentID string) (*models.EnrollmentResponse, error) {
	if s == nil || s.store == nil {
		return nil, fmt.Errorf("enrollment store not initialized")
	}
	enrollmentID = strings.TrimSpace(enrollmentID)
	if enrollmentID == "" {
		return nil, fmt.Errorf("%w: enrollment ID is required", ErrInvalidRequest)
	}
	enrollment, found := s.store.GetDeviceEnrollment(enrollmentID)
	if !found {
		return nil, ErrNotFound
	}

	response := &models.EnrollmentResponse{
		ID:     enrollment.ID,
		Status: enrollment.Status,
	}
	switch enrollment.Status {
	case "approved":
		response.CertPEM = enrollment.CertPEM
		response.Message = "Certificate issued"
	case "pending":
		response.Message = "Awaiting admin approval"
	case "revoked":
		response.Message = "Enrollment has been revoked"
	}
	return response, nil
}

func (s *Service) ListDeviceEnrollments() ([]*models.DeviceEnrollment, error) {
	if s == nil || s.store == nil {
		return nil, fmt.Errorf("enrollment store not initialized")
	}
	return s.store.ListDeviceEnrollments(), nil
}
