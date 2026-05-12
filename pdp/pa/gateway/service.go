package gateway

import (
	"bytes"
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
		TokenExpiresAt:    now.Add(gatewayEnrollmentTokenTTL).Format(time.RFC3339),
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
	tokenHashRaw := sha256.Sum256([]byte(enrollmentToken))
	tokenHash := hex.EncodeToString(tokenHashRaw[:])
	gateway.EnrollmentToken = tokenHash
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
	if gateway.Status == "revoked" {
		return nil, fmt.Errorf("%w: revoked gateways cannot be enrolled", ErrForbidden)
	}
	if strings.TrimSpace(gateway.TenantID) == "" {
		return nil, fmt.Errorf("%w: gateway tenant_id is required before enrollment", ErrInvalidRequest)
	}
	if requestGatewayID := strings.TrimSpace(req.GatewayID); requestGatewayID != "" && requestGatewayID != gateway.ID {
		return nil, fmt.Errorf("%w: enrollment gateway_id does not match token gateway", ErrForbidden)
	}
	if requestTenantID := strings.TrimSpace(req.TenantID); requestTenantID != "" && requestTenantID != gateway.TenantID {
		return nil, fmt.Errorf("%w: enrollment tenant_id does not match token tenant", ErrForbidden)
	}

	csr, err := parseGatewayCSR(req.CSRPEM)
	if err != nil {
		return nil, err
	}
	fqdn := strings.TrimSpace(req.FQDN)
	if fqdn == "" {
		fqdn = strings.TrimSpace(gateway.FQDN)
	}
	if err := validateGatewayCSRIdentity(csr, gateway, fqdn); err != nil {
		return nil, err
	}
	if !s.store.ConsumeGatewayEnrollmentToken(gateway.ID, req.Token, s.clock()) {
		return nil, ErrInvalidEnrollmentToken
	}

	certPEM, err := s.signer([]byte(req.CSRPEM), gatewayCertificateValidityDays, s.pkiRole)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	if err := validateGatewayCertificate(certPEM, csr, gateway); err != nil {
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
	if err := validateGatewayCSRIdentity(csr, gateway, strings.TrimSpace(gateway.FQDN)); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrForbidden, err)
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
	if err := validateGatewayCertificate(certPEM, csr, gateway); err != nil {
		return nil, err
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

func (s *Service) validateTenant(tenantID string) (string, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return "", fmt.Errorf("%w: tenant_id is required", ErrInvalidRequest)
	}
	tenant, found := s.store.GetTenant(tenantID)
	if !found || tenant == nil || !tenant.Enabled {
		return "", fmt.Errorf("%w: tenant not found or disabled", ErrInvalidRequest)
	}
	return tenantID, nil
}

func (s *Service) validateAssignedResourcesTenant(tenantID string, resourceIDs []string) error {
	tenantID = strings.TrimSpace(tenantID)
	for _, resourceID := range resourceIDs {
		resourceID = strings.TrimSpace(resourceID)
		if resourceID == "" {
			continue
		}
		resource, found := s.store.GetResource(resourceID)
		if !found || resource == nil {
			return fmt.Errorf("%w: assigned resource %s not found", ErrInvalidRequest, resourceID)
		}
		if strings.TrimSpace(resource.TenantID) != "" && !strings.EqualFold(resource.TenantID, tenantID) {
			return fmt.Errorf("%w: assigned resource %s belongs to a different tenant", ErrInvalidRequest, resourceID)
		}
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
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: CSR signature invalid: %v", ErrInvalidCSR, err)
	}
	return csr, nil
}

func validateGatewayCSRIdentity(csr *x509.CertificateRequest, gateway *models.Gateway, fqdn string) error {
	if csr == nil || gateway == nil {
		return fmt.Errorf("%w: CSR and gateway identity are required", ErrInvalidCSR)
	}
	tenantID := strings.TrimSpace(gateway.TenantID)
	gatewayID := strings.TrimSpace(gateway.ID)
	if tenantID == "" || gatewayID == "" {
		return fmt.Errorf("%w: gateway tenant_id and gateway_id are required", ErrInvalidCSR)
	}
	if !csrHasGatewayIdentity(csr, tenantID, gatewayID) {
		return fmt.Errorf("%w: CSR must include URI SAN %q", ErrInvalidCSR, GatewayIdentityURI(tenantID, gatewayID))
	}
	if fqdn = strings.TrimSpace(fqdn); fqdn != "" && !stringSliceContainsFold(csr.DNSNames, fqdn) {
		return fmt.Errorf("%w: CSR DNS SAN must include gateway FQDN %q", ErrInvalidCSR, fqdn)
	}
	return nil
}

func validateGatewayCertificate(certPEM []byte, csr *x509.CertificateRequest, gateway *models.Gateway) error {
	cert, err := parseLeafCertificate(certPEM)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCSR, err)
	}
	if cert.IsCA {
		return fmt.Errorf("%w: issued gateway certificate must not be a CA", ErrInvalidCSR)
	}
	if !certificateHasGatewayIdentity(cert, gateway.TenantID, gateway.ID) {
		return fmt.Errorf("%w: issued certificate does not contain expected gateway URI SAN", ErrInvalidCSR)
	}
	if !publicKeysEqual(cert.PublicKey, csr.PublicKey) {
		return fmt.Errorf("%w: issued certificate public key does not match CSR", ErrInvalidCSR)
	}
	if !extKeyUsageContains(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return fmt.Errorf("%w: issued gateway certificate must allow client authentication", ErrInvalidCSR)
	}
	return nil
}

func parseLeafCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("certificate PEM is invalid")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func publicKeysEqual(left, right interface{}) bool {
	leftDER, err := x509.MarshalPKIXPublicKey(left)
	if err != nil {
		return false
	}
	rightDER, err := x509.MarshalPKIXPublicKey(right)
	if err != nil {
		return false
	}
	return bytes.Equal(leftDER, rightDER)
}

func extKeyUsageContains(usages []x509.ExtKeyUsage, expected x509.ExtKeyUsage) bool {
	for _, usage := range usages {
		if usage == expected {
			return true
		}
	}
	return false
}

func stringSliceContainsFold(values []string, expected string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), expected) {
			return true
		}
	}
	return false
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
		TenantID:          gateway.TenantID,
		Name:              gateway.Name,
		FQDN:              gateway.FQDN,
		Status:            gateway.Status,
		ListenAddr:        gateway.ListenAddr,
		PublicIP:          gateway.PublicIP,
		OIDCClientID:      gateway.OIDCClientID,
		EnrollmentToken:   "", // Never expose token hash — admin gets plaintext at creation only
		TokenExpiresAt:    gateway.TokenExpiresAt,
		CertExpiresAt:     gateway.CertExpiresAt,
		AssignedResources: append([]string(nil), gateway.AssignedResources...),
		AuthMode:          defaultGatewayAuthMode,
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
	copy.TenantIDs = append([]string(nil), gateway.TenantIDs...)
	copy.EnrollmentToken = "" // Never expose token hash — defense in depth
	copy.OIDCClientSecret = ""
	copy.CertPEM = ""
	copy.AuthMode = defaultGatewayAuthMode
	copy.FederationConfig = nil
	return &copy
}

func gatewaySubjectID(gatewayID string) string {
	return "gateway:" + gatewayID
}
