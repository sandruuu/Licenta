package enrollment

import (
	"fmt"
	"log"
	"strings"
	"time"

	"pdp/models"
)

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
