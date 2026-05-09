package gateway

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"pdp/models"
	"pdp/store"
)

const (
	gatewayCertificateValidityDays = 7
	gatewayEnrollmentTokenTTL      = time.Hour
	gatewayIDBytes                 = 16
	gatewayEnrollmentTokenBytes    = 32

	defaultGatewayAuthMode   = "builtin"
	federatedGatewayAuthMode = "federated"
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

type Service struct {
	store   *store.Store
	pkiRole string
	signer  CertificateSigner
	revoker CertificateRevoker
	now     func() time.Time
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

func NewService(store *store.Store, pkiRole string) *Service {
	return &Service{store: store, pkiRole: strings.TrimSpace(pkiRole), now: time.Now}
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
	authMode := strings.TrimSpace(req.AuthMode)
	if authMode == "" {
		authMode = defaultGatewayAuthMode
	}
	if authMode != defaultGatewayAuthMode && authMode != federatedGatewayAuthMode {
		return nil, fmt.Errorf("%w: auth_mode must be 'builtin' or 'federated'", ErrInvalidRequest)
	}

	var federationConfig *models.FederationConfig
	if authMode == federatedGatewayAuthMode {
		if req.FederationConfig == nil || strings.TrimSpace(req.FederationConfig.Issuer) == "" || strings.TrimSpace(req.FederationConfig.ClientID) == "" {
			return nil, fmt.Errorf("%w: federation_config.issuer and federation_config.client_id are required when auth_mode='federated'", ErrInvalidRequest)
		}
		federationConfig = cloneFederationConfig(req.FederationConfig)
		federationConfig.Issuer = strings.TrimSpace(federationConfig.Issuer)
		federationConfig.ClientID = strings.TrimSpace(federationConfig.ClientID)
		if federationConfig.Scopes == "" {
			federationConfig.Scopes = "openid profile email"
		}
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
	gateway := &models.Gateway{
		ID:                gatewayID,
		Name:              name,
		FQDN:              strings.TrimSpace(req.FQDN),
		EnrollmentToken:   enrollmentToken,
		TokenExpiresAt:    now.Add(gatewayEnrollmentTokenTTL).Format(time.RFC3339),
		Status:            "pending",
		AssignedResources: append([]string(nil), req.AssignedResources...),
		AuthMode:          authMode,
		FederationConfig:  federationConfig,
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
	if req.AssignedResources != nil {
		gateway.AssignedResources = append([]string(nil), req.AssignedResources...)
	}
	if req.AuthMode == defaultGatewayAuthMode || req.AuthMode == federatedGatewayAuthMode {
		gateway.AuthMode = req.AuthMode
		if req.AuthMode == defaultGatewayAuthMode {
			gateway.FederationConfig = nil
		}
	}
	if req.FederationConfig != nil && gateway.AuthMode == federatedGatewayAuthMode {
		incoming := cloneFederationConfig(req.FederationConfig)
		if incoming.ClientSecret == "" && gateway.FederationConfig != nil {
			incoming.ClientSecret = gateway.FederationConfig.ClientSecret
		}
		gateway.FederationConfig = incoming
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
		s.revoker(gateway.CertSerial, gateway.CertPEM, gatewaySubjectID(gateway.ID), s.clock().Add(gatewayCertificateValidityDays*24*time.Hour))
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
	gateway.EnrollmentToken = enrollmentToken
	gateway.TokenExpiresAt = now.Add(gatewayEnrollmentTokenTTL).Format(time.RFC3339)
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
		s.revoker(gateway.CertSerial, gateway.CertPEM, gatewaySubjectID(gateway.ID), s.clock().Add(gatewayCertificateValidityDays*24*time.Hour))
	}
	return gateway, nil
}

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

	certPEM, err := s.signer([]byte(req.CSRPEM), gatewayCertificateValidityDays, s.pkiRole)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	certFingerprint, certSerial := certificateIdentity(certPEM)

	now := s.clock()
	fqdn := strings.TrimSpace(req.FQDN)
	if fqdn == "" {
		fqdn = gateway.FQDN
	}
	gateway.Status = "enrolled"
	gateway.EnrollmentToken = ""
	gateway.TokenExpiresAt = ""
	gateway.CertPEM = string(certPEM)
	gateway.CertFingerprint = certFingerprint
	gateway.CertSerial = certSerial
	gateway.CertExpiresAt = now.Add(gatewayCertificateValidityDays * 24 * time.Hour).Format(time.RFC3339)
	gateway.OIDCClientID = ""
	gateway.OIDCClientSecret = ""
	if fqdn != "" {
		gateway.FQDN = fqdn
	}
	if name := strings.TrimSpace(req.Name); name != "" {
		gateway.Name = name
	}
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
	if csr.Subject.CommonName != gateway.FQDN {
		return nil, fmt.Errorf("%w: CSR CommonName does not match authenticated gateway FQDN", ErrForbidden)
	}

	oldSerial := gateway.CertSerial
	oldCertPEM := gateway.CertPEM
	oldExpiresOn := s.clock().Add(gatewayCertificateValidityDays * 24 * time.Hour)
	if parsedExpiry, err := time.Parse(time.RFC3339, gateway.CertExpiresAt); err == nil {
		oldExpiresOn = parsedExpiry
	}

	certPEM, err := s.signer([]byte(csrPEM), gatewayCertificateValidityDays, s.pkiRole)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	certFingerprint, certSerial := certificateIdentity(certPEM)
	now := s.clock()
	gateway.CertPEM = string(certPEM)
	gateway.CertFingerprint = certFingerprint
	gateway.CertSerial = certSerial
	gateway.CertExpiresAt = now.Add(gatewayCertificateValidityDays * 24 * time.Hour).Format(time.RFC3339)
	gateway.UpdatedAt = now
	gateway.LastSeenAt = now
	s.store.SaveGateway(gateway)

	if oldSerial != "" && oldSerial != gateway.CertSerial && s.revoker != nil {
		s.revoker(oldSerial, oldCertPEM, gatewaySubjectID(gateway.ID), oldExpiresOn)
	}

	return &RenewalResult{Gateway: gateway, CertPEM: certPEM}, nil
}

func (s *Service) gatewayByID(id string) (*models.Gateway, error) {
	if err := s.readyStore(); err != nil {
		return nil, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("%w: gateway ID required", ErrInvalidRequest)
	}
	gateway, found := s.store.GetGateway(id)
	if !found {
		return nil, ErrGatewayNotFound
	}
	return gateway, nil
}

func (s *Service) ready() error {
	if err := s.readyStore(); err != nil {
		return err
	}
	if s.signer == nil {
		return fmt.Errorf("%w: PKI signer not initialized", ErrGatewaySigning)
	}
	return nil
}

func (s *Service) readyStore() error {
	if s == nil || s.store == nil {
		return ErrGatewayStoreUnavailable
	}
	return nil
}

func (s *Service) clock() time.Time {
	if s != nil && s.now != nil {
		return s.now()
	}
	return time.Now()
}

func tokenExpired(value string, now time.Time) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	expiresAt, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return false
	}
	return now.After(expiresAt)
}

func parseGatewayCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, fmt.Errorf("%w: invalid CSR PEM", ErrInvalidCSR)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	return csr, nil
}

func certificateIdentity(certPEM []byte) (string, string) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", ""
	}
	fingerprint := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(fingerprint[:]), cert.SerialNumber.String()
}

func randomHex(bytesLen int) (string, error) {
	if bytesLen <= 0 {
		return "", fmt.Errorf("random byte length must be positive")
	}
	randomBytes := make([]byte, bytesLen)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(randomBytes), nil
}

func gatewayListItem(gateway *models.Gateway) GatewayListItem {
	return GatewayListItem{
		ID:                gateway.ID,
		Name:              gateway.Name,
		FQDN:              gateway.FQDN,
		Status:            gateway.Status,
		ListenAddr:        gateway.ListenAddr,
		PublicIP:          gateway.PublicIP,
		OIDCClientID:      gateway.OIDCClientID,
		EnrollmentToken:   gateway.EnrollmentToken,
		TokenExpiresAt:    gateway.TokenExpiresAt,
		CertExpiresAt:     gateway.CertExpiresAt,
		AssignedResources: append([]string(nil), gateway.AssignedResources...),
		AuthMode:          gateway.AuthMode,
		FederationConfig:  sanitizeFederationConfig(gateway.FederationConfig),
		CreatedAt:         gateway.CreatedAt,
		UpdatedAt:         gateway.UpdatedAt,
		LastSeenAt:        gateway.LastSeenAt,
	}
}

func sanitizeGatewayForAdmin(gateway *models.Gateway) *models.Gateway {
	if gateway == nil {
		return nil
	}
	copy := *gateway
	copy.AssignedResources = append([]string(nil), gateway.AssignedResources...)
	copy.OIDCClientSecret = ""
	copy.CertPEM = ""
	copy.FederationConfig = sanitizeFederationConfig(gateway.FederationConfig)
	return &copy
}

func sanitizeFederationConfig(config *models.FederationConfig) *models.FederationConfig {
	clone := cloneFederationConfig(config)
	if clone != nil {
		clone.ClientSecret = ""
	}
	return clone
}

func cloneFederationConfig(config *models.FederationConfig) *models.FederationConfig {
	if config == nil {
		return nil
	}
	clone := *config
	if config.ClaimMapping != nil {
		clone.ClaimMapping = make(map[string]string, len(config.ClaimMapping))
		for key, value := range config.ClaimMapping {
			clone.ClaimMapping[key] = value
		}
	}
	return &clone
}

func gatewaySubjectID(gatewayID string) string {
	return "gateway:" + gatewayID
}
