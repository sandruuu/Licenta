package enrollment

import (
	"fmt"
	"log"
	"strings"
	"time"

	"pdp/certs"
	"pdp/models"
	"pdp/util"
)

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
	csr, _, err := ParseCSR(csrPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	if err := ValidateCSRDeviceIdentity(csr, enrollment.DeviceID); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	if enrollment.PublicKeyFingerprint != "" && enrollment.PublicKeyFingerprint != csrFingerprint {
		return nil, nil, fmt.Errorf("%w: public key fingerprint does not match enrollment", ErrForbidden)
	}

	enrollment.Component = NormalizeComponent(enrollment.Component)
	certPEM, err := s.signer([]byte(csrPEM), s.certificateValidityDays, s.resolveDeviceRole(enrollment.Component))
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
	enrollment.ExpiresAt = now.Add(s.certificateValidity())
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
	deviceID := strings.TrimSpace(req.DeviceID)
	if err := ValidateCSRDeviceIdentity(csr, deviceID); err != nil {
		return nil, nil, false, err
	}
	if err := ValidateCSREmailIdentity(csr, username); err != nil {
		return nil, nil, false, err
	}

	component := NormalizeComponent(req.Component)
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

	certPEM, err := s.signer([]byte(csrPEM), s.certificateValidityDays, s.resolveDeviceRole(component))
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
		ExpiresAt:            now.Add(s.certificateValidity()),
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
	csr, _, err := ParseCSR(csrPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	if err := ValidateCSRDeviceIdentity(csr, deviceID); err != nil {
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

	certPEM, err := s.signer([]byte(csrPEM), s.certificateValidityDays, s.resolveDeviceRole(enrollment.Component))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrSigning, err)
	}

	enrollment.CSRPEM = csrPEM
	enrollment.CertPEM = string(certPEM)
	enrollment.CertFingerprint, _ = certs.CertFingerprint(certPEM)
	enrollment.CertSerial = certificateSerial(certPEM)
	enrollment.ExpiresAt = time.Now().Add(s.certificateValidity())
	s.store.SaveDeviceEnrollment(enrollment)

	return enrollment, certPEM, nil
}
