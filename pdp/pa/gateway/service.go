package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"pdp/models"
	"pdp/pa/events"
	"pdp/store"
)

const (
	defaultCertificateValidityDays = 7
	defaultEnrollmentTokenTTL      = time.Hour
	gatewayIDBytes                 = 16
	gatewayEnrollmentTokenBytes    = 32
)

var (
	ErrInvalidRequest          = errors.New("invalid gateway request")
	ErrInvalidEnrollmentToken  = errors.New("invalid enrollment token")
	ErrEnrollmentTokenExpired  = errors.New("enrollment token has expired")
	ErrGatewayAlreadyEnrolled  = errors.New("gateway is already enrolled")
	ErrGatewayNotFound         = errors.New("gateway not found")
	ErrInvalidCSR              = errors.New("invalid CSR")
	ErrForbidden               = errors.New("forbidden gateway operation")
	ErrGatewaySigning          = errors.New("gateway certificate signing failed")
	ErrGatewayTokenGeneration  = errors.New("gateway token generation failed")
	ErrGatewayPersistence      = errors.New("gateway persistence failed")
	ErrGatewayStoreUnavailable = errors.New("gateway store not initialized")
)

type CertificateProfile struct {
	CommonName string
	DNSNames   []string
	URISANs    []string
}

type CertificateSigner func(csrPEM []byte, validDays int, role string, profile CertificateProfile) ([]byte, error)

type CertificateRevoker func(serial, certPEM, subjectID string, expiresOn time.Time)

type EventPublisher interface {
	PublishCAEPEvent(eventType string, fields map[string]string)
}

type Config struct {
	CertificateValidityDays int
	EnrollmentTokenTTL      time.Duration
}

type Service struct {
	store                   *store.Store
	pkiRole                 string
	certificateValidityDays int
	enrollmentTokenTTL      time.Duration
	signer                  CertificateSigner
	revoker                 CertificateRevoker
	publisher               EventPublisher
	now                     func() time.Time
}

type EnrollmentResult struct {
	Gateway *models.Gateway
	CertPEM []byte
}

type RenewalResult struct {
	Gateway *models.Gateway
	CertPEM []byte
}

type CreateGatewayRequest struct {
	OrganizationID    string   `json:"organization_id"`
	Name              string   `json:"name"`
	FQDN              string   `json:"fqdn,omitempty"`
	AssignedResources []string `json:"assigned_resources,omitempty"`
}

type CreateGatewayResult struct {
	Gateway         *models.Gateway
	EnrollmentToken string
}

type UpdateGatewayRequest struct {
	OrganizationID    string   `json:"organization_id,omitempty"`
	Name              string   `json:"name,omitempty"`
	FQDN              string   `json:"fqdn,omitempty"`
	AssignedResources []string `json:"assigned_resources,omitempty"`
}

type RegenerateTokenResult struct {
	Gateway         *models.Gateway
	EnrollmentToken string
	TokenExpiresAt  string
}

type GatewayListItem struct {
	ID                string    `json:"id"`
	OrganizationID    string    `json:"organization_id"`
	Name              string    `json:"name"`
	FQDN              string    `json:"fqdn"`
	Status            string    `json:"status"`
	ListenAddr        string    `json:"listen_addr,omitempty"`
	PublicIP          string    `json:"public_ip,omitempty"`
	EnrollmentToken   string    `json:"enrollment_token,omitempty"`
	TokenExpiresAt    string    `json:"token_expires_at,omitempty"`
	CertExpiresAt     string    `json:"cert_expires_at,omitempty"`
	AssignedResources []string  `json:"assigned_resources,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	LastSeenAt        time.Time `json:"last_seen_at,omitempty"`
}

func NewService(store *store.Store, pkiRole string, cfgs ...Config) *Service {
	cfg := Config{
		CertificateValidityDays: defaultCertificateValidityDays,
		EnrollmentTokenTTL:      defaultEnrollmentTokenTTL,
	}
	if len(cfgs) > 0 {
		if cfgs[0].CertificateValidityDays > 0 {
			cfg.CertificateValidityDays = cfgs[0].CertificateValidityDays
		}
		if cfgs[0].EnrollmentTokenTTL > 0 {
			cfg.EnrollmentTokenTTL = cfgs[0].EnrollmentTokenTTL
		}
	}
	return &Service{
		store:                   store,
		pkiRole:                 strings.TrimSpace(pkiRole),
		certificateValidityDays: cfg.CertificateValidityDays,
		enrollmentTokenTTL:      cfg.EnrollmentTokenTTL,
		now:                     time.Now,
	}
}

func (s *Service) SetCertificateAuthority(signer CertificateSigner, revoker CertificateRevoker) {
	if s == nil {
		return
	}
	s.signer = signer
	s.revoker = revoker
}

func (s *Service) SetEventPublisher(publisher EventPublisher) {
	if s == nil {
		return
	}
	s.publisher = publisher
}

func (s *Service) ListGatewaySummaries() ([]GatewayListItem, error) {
	if err := s.readyStore(); err != nil {
		return nil, err
	}
	gateways := s.store.ListGateways()
	if gateways == nil {
		return []GatewayListItem{}, nil
	}
	items := make([]GatewayListItem, 0, len(gateways))
	for _, gateway := range gateways {
		if gateway == nil {
			continue
		}
		items = append(items, gatewayListItem(gateway))
	}
	return items, nil
}

func (s *Service) CreateGateway(req CreateGatewayRequest) (*CreateGatewayResult, error) {
	if err := s.readyStore(); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", ErrInvalidRequest)
	}
	organizationID, err := s.validateOrganization(req.OrganizationID)
	if err != nil {
		return nil, err
	}
	if err := s.validateAssignedResourcesOrganization(organizationID, req.AssignedResources); err != nil {
		return nil, err
	}

	gatewayID, err := randomHex(gatewayIDBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: generate gateway ID: %v", ErrGatewayTokenGeneration, err)
	}
	enrollmentToken, err := randomHex(gatewayEnrollmentTokenBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: generate enrollment token: %v", ErrGatewayTokenGeneration, err)
	}

	now := s.clock()
	tokenHashRaw := sha256.Sum256([]byte(enrollmentToken))
	tokenHash := hex.EncodeToString(tokenHashRaw[:])
	gateway := &models.Gateway{
		ID:                gatewayID,
		OrganizationID:    organizationID,
		OrganizationIDs:   []string{organizationID},
		Name:              name,
		FQDN:              strings.TrimSpace(req.FQDN),
		EnrollmentToken:   tokenHash,
		TokenExpiresAt:    now.Add(s.enrollmentTokenTTL).Format(time.RFC3339),
		Status:            "pending",
		AssignedResources: append([]string(nil), req.AssignedResources...),
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	s.store.SaveGateway(gateway)

	return &CreateGatewayResult{Gateway: gateway, EnrollmentToken: enrollmentToken}, nil
}

func (s *Service) GetGatewayForAdmin(id string) (*models.Gateway, error) {
	gateway, err := s.gatewayByID(id)
	if err != nil {
		return nil, err
	}
	return sanitizeGatewayForAdmin(gateway), nil
}

func (s *Service) UpdateGateway(id string, req UpdateGatewayRequest) (*models.Gateway, error) {
	gateway, err := s.gatewayByID(id)
	if err != nil {
		return nil, err
	}

	if req.Name != "" {
		gateway.Name = req.Name
	}
	if req.FQDN != "" {
		gateway.FQDN = req.FQDN
	}
	targetOrganizationID := gateway.OrganizationID
	requestedOrganizationID := req.OrganizationID
	if strings.TrimSpace(requestedOrganizationID) != "" && !strings.EqualFold(requestedOrganizationID, gateway.OrganizationID) {
		if gateway.Status == "enrolled" {
			return nil, fmt.Errorf("%w: enrolled gateways cannot be moved between organizations", ErrInvalidRequest)
		}
		organizationID, err := s.validateOrganization(requestedOrganizationID)
		if err != nil {
			return nil, err
		}
		targetOrganizationID = organizationID
	}
	targetResources := gateway.AssignedResources
	if req.AssignedResources != nil {
		targetResources = append([]string(nil), req.AssignedResources...)
	}
	if err := s.validateAssignedResourcesOrganization(targetOrganizationID, targetResources); err != nil {
		return nil, err
	}
	if !strings.EqualFold(targetOrganizationID, gateway.OrganizationID) {
		gateway.OrganizationID = targetOrganizationID
		gateway.OrganizationIDs = []string{targetOrganizationID}
	}
	if req.AssignedResources != nil {
		gateway.AssignedResources = targetResources
	}
	gateway.UpdatedAt = s.clock()
	s.store.SaveGateway(gateway)
	return gateway, nil
}

func (s *Service) DeleteGateway(id string) (*models.Gateway, error) {
	gateway, err := s.gatewayByID(id)
	if err != nil {
		return nil, err
	}
	if gateway.CertSerial != "" && s.revoker != nil {
		s.revoker(gateway.CertSerial, gateway.CertPEM, gatewaySubjectID(gateway.ID), s.clock().Add(s.certificateValidity()))
	}
	if !s.store.DeleteGateway(gateway.ID) {
		return nil, fmt.Errorf("%w: delete gateway", ErrGatewayPersistence)
	}
	s.publishGatewayRevoked(gateway, "gateway_deleted")
	return gateway, nil
}

func (s *Service) RegenerateEnrollmentToken(id string) (*RegenerateTokenResult, error) {
	gateway, err := s.gatewayByID(id)
	if err != nil {
		return nil, err
	}
	enrollmentToken, err := randomHex(gatewayEnrollmentTokenBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: generate enrollment token: %v", ErrGatewayTokenGeneration, err)
	}
	now := s.clock()
	tokenHashRaw := sha256.Sum256([]byte(enrollmentToken))
	tokenHash := hex.EncodeToString(tokenHashRaw[:])
	gateway.EnrollmentToken = tokenHash
	gateway.TokenExpiresAt = now.Add(s.enrollmentTokenTTL).Format(time.RFC3339)
	gateway.Status = "pending"
	gateway.UpdatedAt = now
	s.store.SaveGateway(gateway)
	return &RegenerateTokenResult{Gateway: gateway, EnrollmentToken: enrollmentToken, TokenExpiresAt: gateway.TokenExpiresAt}, nil
}

func (s *Service) RevokeGateway(id string) (*models.Gateway, error) {
	gateway, err := s.gatewayByID(id)
	if err != nil {
		return nil, err
	}
	revokedSerial := gateway.CertSerial
	revokedCertPEM := gateway.CertPEM
	gateway.Status = "revoked"
	gateway.EnrollmentToken = ""
	gateway.TokenExpiresAt = ""
	gateway.UpdatedAt = s.clock()

	if revokedSerial != "" && s.revoker != nil {
		s.revoker(revokedSerial, revokedCertPEM, gatewaySubjectID(gateway.ID), s.clock().Add(s.certificateValidity()))
	}
	gateway.CertPEM = ""
	gateway.CertFingerprint = ""
	gateway.CertSerial = ""
	gateway.CertExpiresAt = ""
	s.store.SaveGateway(gateway)
	s.publishGatewayRevoked(gateway, "gateway_revoked")
	return gateway, nil
}

func (s *Service) publishGatewayRevoked(gateway *models.Gateway, reason string) {
	if s == nil || s.publisher == nil || gateway == nil {
		return
	}
	s.publisher.PublishCAEPEvent(events.TopicGatewayRevoked, map[string]string{
		"gateway_id":      gateway.ID,
		"organization_id": gateway.OrganizationID,
		"reason":          reason,
	})
}
