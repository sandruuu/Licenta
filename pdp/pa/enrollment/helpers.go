package enrollment

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"time"

	"pdp/models"
)

func (s *Service) resolveDeviceRole(component string) string {
	if s.deviceRole == nil {
		return ""
	}
	return s.deviceRole(component)
}

func (s *Service) certificateValidity() time.Duration {
	if s != nil && s.certificateValidityDays > 0 {
		return time.Duration(s.certificateValidityDays) * 24 * time.Hour
	}
	return time.Duration(defaultCertificateValidityDays) * 24 * time.Hour
}

func (s *Service) activeBrowserSessionTTL() time.Duration {
	if s != nil && s.browserSessionTTL > 0 {
		return s.browserSessionTTL
	}
	return defaultBrowserSessionTTL
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
