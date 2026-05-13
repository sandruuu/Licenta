package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"pdp/models"
	"pdp/store"
)

const (
	defaultCertificateValidityDays = 7
	defaultEnrollmentTokenTTL      = time.Hour
	gatewayIDBytes                 = 16
	gatewayEnrollmentTokenBytes    = 32

	defaultGatewayAuthMode = "builtin"
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

type CertificateSigner func(csrPEM []byte, validDays int, role string) ([]byte, error)

type CertificateRevoker func(serial, certPEM, subjectID string, expiresOn time.Time)

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
	TenantID          string                   `json:"tenant_id"`
	Name              string                   `json:"name"`
	FQDN              string                   `json:"fqdn,omitempty"`
	AssignedResources []string                 `json:"assigned_resources,omitempty"`
	AuthMode          string                   `json:"auth_mode,omitempty"`
	FederationConfig  *models.FederationConfig `json:"federation_config,omitempty"`
}

type CreateGatewayResult struct {
	Gateway         *models.Gateway
	EnrollmentToken string
}

type UpdateGatewayRequest struct {
	TenantID          string                   `json:"tenant_id,omitempty"`
	Name              string                   `json:"name,omitempty"`
	FQDN              string                   `json:"fqdn,omitempty"`
	AssignedResources []string                 `json:"assigned_resources,omitempty"`
	AuthMode          string                   `json:"auth_mode,omitempty"`
	FederationConfig  *models.FederationConfig `json:"federation_config,omitempty"`
}

type RegenerateTokenResult struct {
	Gateway         *models.Gateway
	EnrollmentToken string
	TokenExpiresAt  string
}

type GatewayListItem struct {
	ID                string                   `json:"id"`
	TenantID          string                   `json:"tenant_id"`
	Name              string                   `json:"name"`
	FQDN              string                   `json:"fqdn"`
	Status            string                   `json:"status"`
	ListenAddr        string                   `json:"listen_addr,omitempty"`
	PublicIP          string                   `json:"public_ip,omitempty"`
	OIDCClientID      string                   `json:"oidc_client_id,omitempty"`
	EnrollmentToken   string                   `json:"enrollment_token,omitempty"`
	TokenExpiresAt    string                   `json:"token_expires_at,omitempty"`
	CertExpiresAt     string                   `json:"cert_expires_at,omitempty"`
	AssignedResources []string                 `json:"assigned_resources,omitempty"`
	AuthMode          string                   `json:"auth_mode"`
	FederationConfig  *models.FederationConfig `json:"federation_config,omitempty"`
	CreatedAt         time.Time                `json:"created_at"`
	UpdatedAt         time.Time                `json:"updated_at"`
	LastSeenAt        time.Time                `json:"last_seen_at,omitempty"`
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
	tenantID, err := s.validateTenant(req.TenantID)
	if err != nil {
		return nil, err
	}
	if err := s.validateAssignedResourcesTenant(tenantID, req.AssignedResources); err != nil {
		return nil, err
	}
	authMode := strings.TrimSpace(req.AuthMode)
	if authMode == "" {
		authMode = defaultGatewayAuthMode
	}
	if authMode != defaultGatewayAuthMode {
		return nil, fmt.Errorf("%w: gateway authentication is configured at tenant level; use tenant identity providers", ErrInvalidRequest)
	}
	if req.FederationConfig != nil {
		return nil, fmt.Errorf("%w: federation_config is not supported on gateways; configure an identity provider on the tenant", ErrInvalidRequest)
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
		TenantID:          tenantID,
		TenantIDs:         []string{tenantID},
		Name:              name,
		FQDN:              strings.TrimSpace(req.FQDN),
		EnrollmentToken:   tokenHash,
		TokenExpiresAt:    now.Add(s.enrollmentTokenTTL).Format(time.RFC3339),
		Status:            "pending",
		AssignedResources: append([]string(nil), req.AssignedResources...),
		AuthMode:          authMode,
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
	targetTenantID := gateway.TenantID
	if strings.TrimSpace(req.TenantID) != "" && !strings.EqualFold(req.TenantID, gateway.TenantID) {
		if gateway.Status == "enrolled" {
			return nil, fmt.Errorf("%w: enrolled gateways cannot be moved between tenants", ErrInvalidRequest)
		}
		tenantID, err := s.validateTenant(req.TenantID)
		if err != nil {
			return nil, err
		}
		targetTenantID = tenantID
	}
	targetResources := gateway.AssignedResources
	if req.AssignedResources != nil {
		targetResources = append([]string(nil), req.AssignedResources...)
	}
	if err := s.validateAssignedResourcesTenant(targetTenantID, targetResources); err != nil {
		return nil, err
	}
	if !strings.EqualFold(targetTenantID, gateway.TenantID) {
		gateway.TenantID = targetTenantID
		gateway.TenantIDs = []string{targetTenantID}
	}
	if req.AssignedResources != nil {
		gateway.AssignedResources = targetResources
	}
	authMode := strings.TrimSpace(req.AuthMode)
	if authMode != "" && authMode != defaultGatewayAuthMode {
		return nil, fmt.Errorf("%w: gateway authentication is configured at tenant level; use tenant identity providers", ErrInvalidRequest)
	}
	if req.FederationConfig != nil {
		return nil, fmt.Errorf("%w: federation_config is not supported on gateways; configure an identity provider on the tenant", ErrInvalidRequest)
	}
	if authMode == defaultGatewayAuthMode {
		gateway.AuthMode = defaultGatewayAuthMode
		gateway.FederationConfig = nil
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
	gateway.Status = "revoked"
	gateway.EnrollmentToken = ""
	gateway.UpdatedAt = s.clock()
	s.store.SaveGateway(gateway)

	if gateway.CertSerial != "" && s.revoker != nil {
		s.revoker(gateway.CertSerial, gateway.CertPEM, gatewaySubjectID(gateway.ID), s.clock().Add(s.certificateValidity()))
	}
	return gateway, nil
}
