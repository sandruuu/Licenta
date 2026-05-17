package gateway

import (
	"fmt"
	"strings"
	"time"

	"pdp/models"
)

func (s *Service) EnrollGateway(req models.GatewayEnrollRequest) (*EnrollmentResult, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	req.Token = strings.TrimSpace(req.Token)
	req.CSRPEM = strings.TrimSpace(req.CSRPEM)
	if req.Token == "" || req.CSRPEM == "" {
		return nil, fmt.Errorf("%w: token and csr_pem are required", ErrInvalidRequest)
	}

	gateway, found := s.store.GetGatewayByToken(req.Token)
	if !found {
		return nil, ErrInvalidEnrollmentToken
	}
	if tokenExpired(gateway.TokenExpiresAt, s.clock()) {
		return nil, ErrEnrollmentTokenExpired
	}
	if gateway.Status == "enrolled" {
		return nil, ErrGatewayAlreadyEnrolled
	}
	if gateway.Status == "revoked" {
		return nil, fmt.Errorf("%w: revoked gateways cannot be enrolled", ErrForbidden)
	}
	if strings.TrimSpace(gateway.TenantID) == "" {
		return nil, fmt.Errorf("%w: gateway organization_id is required before enrollment", ErrInvalidRequest)
	}
	csr, err := parseGatewayCSR(req.CSRPEM)
	if err != nil {
		return nil, err
	}
	fqdn := strings.TrimSpace(gateway.FQDN)
	if fqdn == "" {
		return nil, fmt.Errorf("%w: gateway FQDN is required before enrollment", ErrInvalidRequest)
	}
	if err := validateGatewayCSRRequest(csr, gateway, fqdn); err != nil {
		return nil, err
	}
	if !s.store.ConsumeGatewayEnrollmentToken(gateway.ID, req.Token, s.clock()) {
		return nil, ErrInvalidEnrollmentToken
	}

	profile, err := gatewayCertificateProfile(gateway)
	if err != nil {
		return nil, err
	}
	certPEM, err := s.signer([]byte(req.CSRPEM), s.certificateValidityDays, s.pkiRole, profile)
	if err != nil {
		s.store.SaveGateway(gateway)
		return nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	if err := validateGatewayCertificate(certPEM, csr, gateway); err != nil {
		s.store.SaveGateway(gateway)
		return nil, err
	}
	certFingerprint, certSerial := certificateIdentity(certPEM)

	now := s.clock()
	gateway.Status = "enrolled"
	gateway.EnrollmentToken = ""
	gateway.TokenExpiresAt = ""
	gateway.CertPEM = string(certPEM)
	gateway.CertFingerprint = certFingerprint
	gateway.CertSerial = certSerial
	gateway.CertExpiresAt = now.Add(s.certificateValidity()).Format(time.RFC3339)
	gateway.OIDCClientID = ""
	gateway.OIDCClientSecret = ""
	gateway.UpdatedAt = now
	gateway.LastSeenAt = now
	s.store.SaveGateway(gateway)

	return &EnrollmentResult{Gateway: gateway, CertPEM: certPEM}, nil
}

func (s *Service) RenewGatewayCertificate(gateway *models.Gateway, csrPEM string) (*RenewalResult, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	if gateway == nil {
		return nil, fmt.Errorf("%w: gateway identity not found in request context", ErrForbidden)
	}
	csrPEM = strings.TrimSpace(csrPEM)
	if csrPEM == "" {
		return nil, fmt.Errorf("%w: csr_pem is required", ErrInvalidRequest)
	}
	csr, err := parseGatewayCSR(csrPEM)
	if err != nil {
		return nil, err
	}
	if err := validateGatewayCSRRequest(csr, gateway, strings.TrimSpace(gateway.FQDN)); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrForbidden, err)
	}
	profile, err := gatewayCertificateProfile(gateway)
	if err != nil {
		return nil, err
	}

	oldSerial := gateway.CertSerial
	oldCertPEM := gateway.CertPEM
	oldExpiresOn := s.clock().Add(s.certificateValidity())
	if parsedExpiry, err := time.Parse(time.RFC3339, gateway.CertExpiresAt); err == nil {
		oldExpiresOn = parsedExpiry
	}

	certPEM, err := s.signer([]byte(csrPEM), s.certificateValidityDays, s.pkiRole, profile)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	if err := validateGatewayCertificate(certPEM, csr, gateway); err != nil {
		return nil, err
	}
	certFingerprint, certSerial := certificateIdentity(certPEM)
	now := s.clock()
	gateway.CertPEM = string(certPEM)
	gateway.CertFingerprint = certFingerprint
	gateway.CertSerial = certSerial
	gateway.CertExpiresAt = now.Add(s.certificateValidity()).Format(time.RFC3339)
	gateway.UpdatedAt = now
	gateway.LastSeenAt = now
	s.store.SaveGateway(gateway)

	if oldSerial != "" && oldSerial != gateway.CertSerial && s.revoker != nil {
		s.revoker(oldSerial, oldCertPEM, gatewaySubjectID(gateway.ID), oldExpiresOn)
	}

	return &RenewalResult{Gateway: gateway, CertPEM: certPEM}, nil
}
