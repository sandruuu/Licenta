package enrollment

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"pdp/certs"
	"pdp/models"
	"pdp/store"
	"pdp/util"
)

const endpointCertificateValidityDays = 1

var (
	ErrInvalidRequest      = errors.New("invalid enrollment request")
	ErrInvalidCSR          = errors.New("invalid CSR")
	ErrForbidden           = errors.New("forbidden enrollment operation")
	ErrInvalidState        = errors.New("invalid enrollment state")
	ErrExpiredSession      = errors.New("enrollment session expired")
	ErrNotFound            = errors.New("enrollment not found")
	ErrInvalidToken        = errors.New("invalid enrollment token")
	ErrInvalidParentToken  = errors.New("invalid parent token")
	ErrTokenRevoked        = errors.New("token has been revoked")
	ErrTokenAlreadyUsed    = errors.New("enrollment token has already been used")
	ErrNonceGeneration     = errors.New("failed to generate nonce")
	ErrTokenIssue          = errors.New("failed to generate enrollment token")
	ErrSigning             = errors.New("certificate signing failed")
	ErrAlreadyEnrolled     = errors.New("device already has a valid certificate for this component")
	ErrPendingDifferentKey = errors.New("enrollment already pending with a different device key")
)

type PendingEnrollmentAction string

const (
	PendingEnrollmentCreated         PendingEnrollmentAction = "created"
	PendingEnrollmentAlreadyPending  PendingEnrollmentAction = "already_pending"
	PendingEnrollmentAlreadyApproved PendingEnrollmentAction = "already_approved"
)

type PendingEnrollmentResult struct {
	Enrollment *models.DeviceEnrollment
	Action     PendingEnrollmentAction
}

type BrowserEnrollSessionCompletion struct {
	Session    *models.PendingEnrollSession
	Enrollment *models.DeviceEnrollment
	CertPEM    []byte
	Reused     bool
}

type BrowserEnrollSessionStatus struct {
	Status  string
	CertPEM string
	CAPEM   string
	Message string
}

type ESTEnrollmentIdentity struct {
	DeviceID       string
	UserID         string
	Username       string
	TokenID        string
	TokenExpiresAt time.Time
}

type ESTEnrollmentResult struct {
	Enrollment *models.DeviceEnrollment
	CertPEM    []byte
	Reused     bool
}

type EnrollmentTokenParent struct {
	TokenID  string
	Purpose  string
	UserID   string
	Username string
	Role     string
	DeviceID string
}

type EnrollmentTokenIssueRequest struct {
	DeviceID string
	Nonce    string
	UserSID  string
}

type EnrollmentTokenIssueResult struct {
	EnrollmentToken string
	TokenType       string
	ExpiresIn       int
	DeviceID        string
	Nonce           string
	UserSID         string
	UserEmail       string
}

type CertificateSigner func(csrPEM []byte, validDays int, role string) ([]byte, error)

type CertificateRevoker func(serial, certPEM, subjectID string, expiresOn time.Time)

type DeviceRoleResolver func(component string) string

type EnrollmentTokenIssuer func(userID, username, role, deviceID, nonce, userSID string) (string, time.Duration, error)

type Service struct {
	store                 *store.Store
	signer                CertificateSigner
	revoker               CertificateRevoker
	deviceRole            DeviceRoleResolver
	enrollmentTokenIssuer EnrollmentTokenIssuer
}

func NewService(store *store.Store) *Service {
	return &Service{store: store}
}

func (s *Service) SetCertificateAuthority(signer CertificateSigner, revoker CertificateRevoker, deviceRole DeviceRoleResolver) {
	if s == nil {
		return
	}
	s.signer = signer
	s.revoker = revoker
	s.deviceRole = deviceRole
}

func (s *Service) SetEnrollmentTokenIssuer(issuer EnrollmentTokenIssuer) {
	if s == nil {
		return
	}
	s.enrollmentTokenIssuer = issuer
}

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
		ExpiresAt:            time.Now().Add(5 * time.Minute),
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

func (s *Service) CompleteESTEnrollment(req models.EnrollmentRequest, identity ESTEnrollmentIdentity) (*ESTEnrollmentResult, error) {
	if s == nil || s.store == nil {
		return nil, fmt.Errorf("enrollment store not initialized")
	}
	if s.signer == nil {
		return nil, fmt.Errorf("PKI signer not initialized")
	}

	tokenDeviceID := strings.TrimSpace(identity.DeviceID)
	deviceID := strings.TrimSpace(req.DeviceID)
	if deviceID == "" {
		deviceID = tokenDeviceID
	}
	if deviceID == "" {
		return nil, fmt.Errorf("%w: device_id is required", ErrInvalidRequest)
	}
	if tokenDeviceID == "" {
		return nil, fmt.Errorf("%w: bearer token is not bound to a device_id", ErrForbidden)
	}
	if tokenDeviceID != deviceID {
		return nil, fmt.Errorf("%w: token device_id does not match enrollment device_id", ErrForbidden)
	}

	csrPEM, err := CanonicalCSRPEM(req.CSRPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	csr, _, err := ParseCSR(csrPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	if csr.Subject.CommonName != deviceID {
		return nil, fmt.Errorf("%w: CSR common name must match device_id", ErrInvalidCSR)
	}
	username := strings.TrimSpace(identity.Username)
	if err := ValidateCSREmailIdentity(csr, username); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	// Verify TPM key proof-of-possession if provided (N3 fix).
	if req.KeyProof != "" {
		csrFingerprint, err := ComputeCSRFingerprint(csrPEM)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to compute CSR fingerprint for key proof: %v", ErrInvalidCSR, err)
		}
		if err := ValidateKeyProof(csr, deviceID, csrFingerprint, req.KeyProof); err != nil {
			log.Printf("[ENROLL] TPM key proof rejected for device %s: %v", deviceID, err)
			return nil, fmt.Errorf("%w: key proof verification failed", ErrForbidden)
		}
		log.Printf("[ENROLL] TPM key proof verified for device %s", deviceID)
	}
	if err := s.ConsumeEnrollmentToken(identity.TokenID, identity.TokenExpiresAt); err != nil {
		return nil, err
	}

	req.DeviceID = deviceID
	req.Component = NormalizeComponent(req.Component)
	req.Hostname = strings.TrimSpace(req.Hostname)
	req.CSRPEM = csrPEM
	enrollment, certPEM, reused, err := s.IssueDeviceCertificate(req, "", username+" (EST)", strings.TrimSpace(identity.UserID), username)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigning, err)
	}
	return &ESTEnrollmentResult{Enrollment: enrollment, CertPEM: certPEM, Reused: reused}, nil
}

func (s *Service) ConsumeEnrollmentToken(tokenID string, expiresAt time.Time) error {
	if s == nil || s.store == nil {
		return fmt.Errorf("enrollment store not initialized")
	}
	tokenID = strings.TrimSpace(tokenID)
	if tokenID == "" || expiresAt.IsZero() {
		return ErrInvalidToken
	}
	if !s.store.ConsumeTokenOnce(tokenID, expiresAt) {
		return ErrTokenAlreadyUsed
	}
	return nil
}

func (s *Service) IssueEnrollmentToken(parent EnrollmentTokenParent, req EnrollmentTokenIssueRequest) (*EnrollmentTokenIssueResult, error) {
	if s == nil || s.store == nil {
		return nil, fmt.Errorf("enrollment store not initialized")
	}
	if s.enrollmentTokenIssuer == nil {
		return nil, fmt.Errorf("enrollment token issuer not initialized")
	}
	if strings.TrimSpace(parent.Purpose) != "" {
		return nil, ErrInvalidParentToken
	}
	if tokenID := strings.TrimSpace(parent.TokenID); tokenID != "" && s.store.IsTokenRevoked(tokenID) {
		return nil, ErrTokenRevoked
	}

	deviceID := strings.TrimSpace(parent.DeviceID)
	if deviceID == "" {
		return nil, fmt.Errorf("%w: parent token is not bound to a device_id", ErrForbidden)
	}
	if requestedDeviceID := strings.TrimSpace(req.DeviceID); requestedDeviceID != "" && requestedDeviceID != deviceID {
		return nil, fmt.Errorf("%w: requested device_id does not match parent token", ErrForbidden)
	}

	nonce := strings.TrimSpace(req.Nonce)
	if nonce == "" {
		generatedNonce, err := randomHexBytes(16)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNonceGeneration, err)
		}
		nonce = generatedNonce
	}
	userSID := strings.TrimSpace(req.UserSID)
	username := strings.TrimSpace(parent.Username)
	enrollmentToken, ttl, err := s.enrollmentTokenIssuer(strings.TrimSpace(parent.UserID), username, strings.TrimSpace(parent.Role), deviceID, nonce, userSID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenIssue, err)
	}

	result := &EnrollmentTokenIssueResult{
		EnrollmentToken: enrollmentToken,
		TokenType:       "Bearer",
		ExpiresIn:       int(ttl.Seconds()),
		DeviceID:        deviceID,
		Nonce:           nonce,
		UserSID:         userSID,
	}
	if strings.Contains(username, "@") {
		result.UserEmail = username
	}
	return result, nil
}

func (s *Service) ApprovePendingEnrollment(enrollmentID, approvedBy string) (*models.DeviceEnrollment, []byte, error) {
	if s == nil || s.store == nil {
		return nil, nil, fmt.Errorf("enrollment store not initialized")
	}
	if s.signer == nil {
		return nil, nil, fmt.Errorf("PKI signer not initialized")
	}
	enrollmentID = strings.TrimSpace(enrollmentID)
	if enrollmentID == "" {
		return nil, nil, fmt.Errorf("%w: enrollment ID is required", ErrInvalidRequest)
	}
	enrollment, found := s.store.GetDeviceEnrollment(enrollmentID)
	if !found {
		return nil, nil, ErrNotFound
	}
	if enrollment.Status != "pending" {
		return nil, nil, fmt.Errorf("%w: enrollment is not pending", ErrInvalidState)
	}

	csrPEM, err := CanonicalCSRPEM(enrollment.CSRPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	csrFingerprint, err := ComputeCSRFingerprint(csrPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	if enrollment.PublicKeyFingerprint != "" && enrollment.PublicKeyFingerprint != csrFingerprint {
		return nil, nil, fmt.Errorf("%w: public key fingerprint does not match enrollment", ErrForbidden)
	}

	enrollment.Component = NormalizeComponent(enrollment.Component)
	certPEM, err := s.signer([]byte(csrPEM), endpointCertificateValidityDays, s.resolveDeviceRole(enrollment.Component))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrSigning, err)
	}

	now := time.Now()
	enrollment.Status = "approved"
	enrollment.CSRPEM = csrPEM
	enrollment.PublicKeyFingerprint = csrFingerprint
	enrollment.CertPEM = string(certPEM)
	enrollment.CertFingerprint, _ = certs.CertFingerprint(certPEM)
	enrollment.CertSerial = certificateSerial(certPEM)
	enrollment.ExpiresAt = now.Add(endpointCertificateValidityDays * 24 * time.Hour)
	enrollment.ApprovedBy = approvedBy
	s.store.SaveDeviceEnrollment(enrollment)

	return enrollment, certPEM, nil
}

func (s *Service) RevokeDeviceEnrollment(enrollmentID string) (*models.DeviceEnrollment, error) {
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
	if enrollment.CertSerial != "" && s.revoker != nil {
		s.revoker(enrollment.CertSerial, enrollment.CertPEM, enrollment.DeviceID, enrollment.ExpiresAt)
	}
	enrollment.Status = "revoked"
	s.store.SaveDeviceEnrollment(enrollment)
	return enrollment, nil
}

func (s *Service) IssueDeviceCertificate(req models.EnrollmentRequest, enrollmentID, approvedBy, userID, username string) (*models.DeviceEnrollment, []byte, bool, error) {
	if s == nil || s.store == nil {
		return nil, nil, false, fmt.Errorf("enrollment store not initialized")
	}
	if s.signer == nil {
		return nil, nil, false, fmt.Errorf("PKI signer not initialized")
	}
	if strings.TrimSpace(req.DeviceID) == "" || strings.TrimSpace(req.CSRPEM) == "" {
		return nil, nil, false, fmt.Errorf("device_id and csr_pem are required")
	}

	csrPEM, err := CanonicalCSRPEM(req.CSRPEM)
	if err != nil {
		return nil, nil, false, err
	}
	csrFingerprint, err := ComputeCSRFingerprint(csrPEM)
	if err != nil {
		return nil, nil, false, err
	}
	csr, _, err := ParseCSR(csrPEM)
	if err != nil {
		return nil, nil, false, err
	}
	if err := ValidateCSREmailIdentity(csr, username); err != nil {
		return nil, nil, false, err
	}

	component := NormalizeComponent(req.Component)
	deviceID := strings.TrimSpace(req.DeviceID)
	if existing, found := s.store.GetDeviceEnrollmentByComponent(deviceID, component); found {
		if existing.Status == "approved" && existing.ExpiresAt.After(time.Now()) && existing.CertPEM != "" {
			if existing.PublicKeyFingerprint == csrFingerprint {
				return existing, []byte(existing.CertPEM), true, nil
			}
			log.Printf("[ENROLL] Device %s re-enrolling endpoint with new key (old_fp=%s, new_fp=%s); revoking old certificate",
				deviceID, ShortFingerprint(existing.PublicKeyFingerprint), ShortFingerprint(csrFingerprint))
			if existing.CertSerial != "" && s.revoker != nil {
				s.revoker(existing.CertSerial, existing.CertPEM, existing.DeviceID, existing.ExpiresAt)
			}
			existing.Status = "revoked"
			s.store.SaveDeviceEnrollment(existing)
		}
	}

	if enrollmentID == "" {
		var genErr error
		enrollmentID, genErr = util.GenerateID("enroll")
		if genErr != nil {
			return nil, nil, false, fmt.Errorf("generate enrollment ID: %w", genErr)
		}
	}

	certPEM, err := s.signer([]byte(csrPEM), endpointCertificateValidityDays, s.resolveDeviceRole(component))
	if err != nil {
		return nil, nil, false, err
	}

	certSerial := certificateSerial(certPEM)
	certFingerprint, _ := certs.CertFingerprint(certPEM)
	now := time.Now()
	enrollment := &models.DeviceEnrollment{
		ID:                   enrollmentID,
		DeviceID:             deviceID,
		Component:            component,
		Hostname:             strings.TrimSpace(req.Hostname),
		PublicKeyFingerprint: csrFingerprint,
		CertFingerprint:      certFingerprint,
		CertSerial:           certSerial,
		Status:               "approved",
		CSRPEM:               csrPEM,
		CertPEM:              string(certPEM),
		EnrolledAt:           now,
		ExpiresAt:            now.Add(endpointCertificateValidityDays * 24 * time.Hour),
		ApprovedBy:           approvedBy,
		UserID:               userID,
		Username:             username,
	}
	s.store.SaveDeviceEnrollment(enrollment)

	if userID != "" {
		s.store.SaveDeviceUser(&models.DeviceUser{
			DeviceID: deviceID,
			UserID:   userID,
			Username: username,
			Role:     "owner",
			BoundAt:  now,
		})
	}

	return enrollment, certPEM, false, nil
}

func (s *Service) RenewDeviceCertificate(req models.EnrollmentRequest, authenticatedEnrollment *models.DeviceEnrollment) (*models.DeviceEnrollment, []byte, error) {
	if s == nil || s.store == nil {
		return nil, nil, fmt.Errorf("enrollment store not initialized")
	}
	if s.signer == nil {
		return nil, nil, fmt.Errorf("PKI signer not initialized")
	}
	if authenticatedEnrollment == nil {
		return nil, nil, fmt.Errorf("%w: device identity not found in request context", ErrForbidden)
	}
	if strings.TrimSpace(req.DeviceID) == "" || strings.TrimSpace(req.CSRPEM) == "" {
		return nil, nil, fmt.Errorf("%w: device_id and csr_pem are required", ErrInvalidRequest)
	}

	deviceID := strings.TrimSpace(req.DeviceID)
	if deviceID != authenticatedEnrollment.DeviceID {
		log.Printf("[ENROLL] Renewal rejected: request device_id=%q does not match authenticated device=%q", deviceID, authenticatedEnrollment.DeviceID)
		return nil, nil, fmt.Errorf("%w: device_id does not match authenticated device", ErrForbidden)
	}

	csrPEM, err := CanonicalCSRPEM(req.CSRPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	csrFingerprint, err := ComputeCSRFingerprint(csrPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}

	component := NormalizeComponent(req.Component)
	if component != authenticatedEnrollment.Component {
		return nil, nil, fmt.Errorf("%w: component does not match authenticated device enrollment", ErrForbidden)
	}
	enrollment, found := s.store.GetDeviceEnrollmentByComponent(deviceID, component)
	if !found {
		return nil, nil, fmt.Errorf("%w: no enrollment found for device", ErrNotFound)
	}
	if enrollment.Status != "approved" {
		return nil, nil, fmt.Errorf("%w: enrollment is not approved (status: %s)", ErrForbidden, enrollment.Status)
	}
	if enrollment.PublicKeyFingerprint != csrFingerprint {
		log.Printf("[ENROLL] Renewal rejected: fingerprint mismatch for device %s (stored=%s computed=%s)",
			deviceID, enrollment.PublicKeyFingerprint, csrFingerprint)
		return nil, nil, fmt.Errorf("%w: public key fingerprint does not match enrollment", ErrForbidden)
	}

	if enrollment.CertSerial != "" && s.revoker != nil {
		s.revoker(enrollment.CertSerial, enrollment.CertPEM, enrollment.DeviceID, enrollment.ExpiresAt)
	}

	certPEM, err := s.signer([]byte(csrPEM), endpointCertificateValidityDays, s.resolveDeviceRole(enrollment.Component))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrSigning, err)
	}

	enrollment.CSRPEM = csrPEM
	enrollment.CertPEM = string(certPEM)
	enrollment.CertFingerprint, _ = certs.CertFingerprint(certPEM)
	enrollment.CertSerial = certificateSerial(certPEM)
	enrollment.ExpiresAt = time.Now().Add(endpointCertificateValidityDays * 24 * time.Hour)
	s.store.SaveDeviceEnrollment(enrollment)

	return enrollment, certPEM, nil
}

func (s *Service) resolveDeviceRole(component string) string {
	if s.deviceRole == nil {
		return ""
	}
	return s.deviceRole(component)
}

type preparedEnrollmentRequest struct {
	deviceID       string
	component      string
	hostname       string
	csrPEM         string
	csrFingerprint string
}

func (s *Service) prepareEnrollmentRequest(req models.EnrollmentRequest) (*preparedEnrollmentRequest, error) {
	if s == nil || s.store == nil {
		return nil, fmt.Errorf("enrollment store not initialized")
	}
	if strings.TrimSpace(req.DeviceID) == "" || strings.TrimSpace(req.CSRPEM) == "" {
		return nil, fmt.Errorf("%w: device_id and csr_pem are required", ErrInvalidRequest)
	}
	csrPEM, err := CanonicalCSRPEM(req.CSRPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	csrFingerprint, err := ComputeCSRFingerprint(csrPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	return &preparedEnrollmentRequest{
		deviceID:       strings.TrimSpace(req.DeviceID),
		component:      NormalizeComponent(req.Component),
		hostname:       strings.TrimSpace(req.Hostname),
		csrPEM:         csrPEM,
		csrFingerprint: csrFingerprint,
	}, nil
}

func (s *Service) revokeChangedKeyEnrollment(existing *models.DeviceEnrollment, csrFingerprint string) {
	if existing == nil {
		return
	}
	log.Printf("[ENROLL] Device %s re-enrolling with new key (old_fp=%s, new_fp=%s); revoking old enrollment",
		existing.DeviceID, ShortFingerprint(existing.PublicKeyFingerprint), ShortFingerprint(csrFingerprint))
	if existing.CertSerial != "" && s.revoker != nil {
		s.revoker(existing.CertSerial, existing.CertPEM, existing.DeviceID, existing.ExpiresAt)
	}
	existing.Status = "revoked"
	s.store.SaveDeviceEnrollment(existing)
}

func generateEnrollmentSecretID() (string, error) {
	return randomHexBytes(32)
}

func randomHexBytes(bytesLen int) (string, error) {
	if bytesLen <= 0 {
		return "", fmt.Errorf("random byte length must be positive")
	}
	randomBytes := make([]byte, bytesLen)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(randomBytes), nil
}

func certificateSerial(certPEM []byte) string {
	if block, _ := pem.Decode(certPEM); block != nil {
		if parsedCert, err := x509.ParseCertificate(block.Bytes); err == nil {
			return parsedCert.SerialNumber.String()
		}
	}
	return ""
}
