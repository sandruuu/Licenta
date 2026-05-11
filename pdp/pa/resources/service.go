package resources

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"pdp/certs"
	"pdp/events"
	"pdp/models"
	"pdp/store"
	"pdp/util"
)

const (
	defaultCertMode       = "manual"
	vaultSignedCertMode   = "vault-signed"
	selfSignedCertMode    = "self-signed"
	defaultCertValidity   = 365
	clientIDRandomBytes   = 9
	clientSecretByteCount = 20
)

var (
	ErrServiceUnavailable = errors.New("resource service is not available")
	ErrInvalidRequest     = errors.New("invalid resource request")
	ErrResourceNotFound   = errors.New("resource not found")
	ErrCredentialIssue    = errors.New("resource credential generation failed")
	ErrCertificateIssue   = errors.New("resource certificate generation failed")
)

type CertificateSigner func(csrPEM []byte, validDays int, role string) ([]byte, error)

type EventPublisher interface {
	PublishCAEPEvent(eventType string, fields map[string]string)
}

type Service struct {
	store   *store.Store
	pkiRole string
	signer  CertificateSigner
	now     func() time.Time

	publisher EventPublisher
}

type GenerateCertificateRequest struct {
	ResourceID string `json:"resource_id"`
	Domain     string `json:"domain"`
	ValidDays  int    `json:"valid_days"`
}

type GenerateCertificateResult struct {
	Resource *models.Resource
	CertInfo *certs.CertInfo
}

func NewService(store *store.Store, pkiRole string) *Service {
	return &Service{store: store, pkiRole: strings.TrimSpace(pkiRole), now: time.Now}
}

func (service *Service) SetCertificateAuthority(signer CertificateSigner) {
	if service == nil {
		return
	}
	service.signer = signer
}

func (service *Service) SetEventPublisher(publisher EventPublisher) {
	if service == nil {
		return
	}
	service.publisher = publisher
}

func (service *Service) ListResources() ([]*models.Resource, error) {
	if err := service.readyStore(); err != nil {
		return nil, err
	}
	return service.store.ListResources(), nil
}

func (service *Service) CreateResource(resource models.Resource) (*models.Resource, error) {
	if err := service.readyStore(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(resource.Name) == "" || strings.TrimSpace(resource.Type) == "" {
		return nil, fmt.Errorf("%w: name and type are required", ErrInvalidRequest)
	}
	resource.Type = normalizeResourceType(resource.Type)
	if !validResourceType(resource.Type) {
		return nil, fmt.Errorf("%w: type must be ssh, rdp, or web", ErrInvalidRequest)
	}
	if err := service.validateResourceScope(&resource); err != nil {
		return nil, err
	}

	now := service.clock()
	resourceID, err := util.GenerateID("res")
	if err != nil {
		return nil, fmt.Errorf("%w: generate resource ID: %v", ErrCredentialIssue, err)
	}
	clientID, clientSecret, err := generateClientCredentials()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCredentialIssue, err)
	}

	resource.ID = resourceID
	resource.CreatedAt = now
	resource.UpdatedAt = now
	if resource.CertMode == "" {
		resource.CertMode = defaultCertMode
	}
	resource.Enabled = true
	resource.ClientID = clientID
	resource.ClientSecret = clientSecret

	if resource.CertMode == selfSignedCertMode || resource.CertMode == vaultSignedCertMode {
		domain := resource.CertDomain
		if domain == "" {
			domain = resource.Host
		}
		certPEM, keyPEM, err := service.signResourceCert(domain, defaultCertValidity)
		if err != nil {
			return nil, err
		}
		resource.CertPEM = string(certPEM)
		resource.KeyPEM = string(keyPEM)
		resource.CertMode = vaultSignedCertMode
		resource.CertExpiry = now.Add(defaultCertValidity * 24 * time.Hour).Format(time.RFC3339)
		resource.CertDomain = domain
	}

	service.store.SaveResource(&resource)
	service.publishResourceEvent(resource.ID, "created", "resource_created")
	return &resource, nil
}

func (service *Service) GetResource(id string) (*models.Resource, error) {
	return service.resourceByID(id)
}

func (service *Service) UpdateResource(id string, fields map[string]json.RawMessage) (*models.Resource, error) {
	existing, err := service.resourceByID(id)
	if err != nil {
		return nil, err
	}
	updated := *existing
	updated.UpdatedAt = service.clock()

	applyStringField(fields, "name", &updated.Name)
	applyStringField(fields, "description", &updated.Description)
	applyStringField(fields, "type", &updated.Type)
	updated.Type = normalizeResourceType(updated.Type)
	applyStringField(fields, "host", &updated.Host)
	applyIntField(fields, "port", &updated.Port)
	applyStringField(fields, "external_url", &updated.ExternalURL)
	applyBoolField(fields, "enabled", &updated.Enabled)
	applyStringSliceField(fields, "tags", &updated.Tags)
	applyStringMapField(fields, "metadata", &updated.Metadata)
	applyStringSliceField(fields, "allowed_roles", &updated.AllowedRoles)
	applyBoolField(fields, "require_mfa", &updated.RequireMFA)
	applyStringField(fields, "cert_mode", &updated.CertMode)
	applyStringField(fields, "cert_pem", &updated.CertPEM)
	applyStringField(fields, "key_pem", &updated.KeyPEM)
	applyStringField(fields, "cert_expiry", &updated.CertExpiry)
	applyStringField(fields, "cert_domain", &updated.CertDomain)
	applyStringField(fields, "tenant_id", &updated.TenantID)
	applyStringField(fields, "gateway_id", &updated.GatewayID)

	if !validResourceType(updated.Type) {
		return nil, fmt.Errorf("%w: type must be ssh, rdp, or web", ErrInvalidRequest)
	}
	if err := service.validateResourceScope(&updated); err != nil {
		return nil, err
	}

	service.store.SaveResource(&updated)
	service.publishResourceEvent(updated.ID, "updated", "resource_updated")
	return &updated, nil
}

func (service *Service) DeleteResource(id string) error {
	if err := service.readyStore(); err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("%w: resource ID required", ErrInvalidRequest)
	}
	if !service.store.DeleteResource(id) {
		return ErrResourceNotFound
	}
	service.publishResourceEvent(id, "deleted", "resource_deleted")
	return nil
}

func (service *Service) RegenerateSecret(id string) (*models.Resource, error) {
	resource, err := service.resourceByID(id)
	if err != nil {
		return nil, err
	}
	secret, err := randomHex(clientSecretByteCount)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCredentialIssue, err)
	}
	resource.ClientSecret = secret
	resource.UpdatedAt = service.clock()
	service.store.SaveResource(resource)
	return resource, nil
}

func (service *Service) GenerateCertificate(req GenerateCertificateRequest) (*GenerateCertificateResult, error) {
	resource, err := service.resourceByID(req.ResourceID)
	if err != nil {
		return nil, err
	}
	domain := strings.TrimSpace(req.Domain)
	if domain == "" {
		domain = resource.Host
	}
	validDays := req.ValidDays
	if validDays <= 0 {
		validDays = defaultCertValidity
	}
	certPEM, keyPEM, err := service.signResourceCert(domain, validDays)
	if err != nil {
		return nil, err
	}
	now := service.clock()
	resource.CertPEM = string(certPEM)
	resource.KeyPEM = string(keyPEM)
	resource.CertMode = vaultSignedCertMode
	resource.CertDomain = domain
	resource.CertExpiry = now.Add(time.Duration(validDays) * 24 * time.Hour).Format(time.RFC3339)
	resource.UpdatedAt = now
	service.store.SaveResource(resource)

	info, _ := certs.ParseCertPEM(resource.CertPEM)
	return &GenerateCertificateResult{Resource: resource, CertInfo: info}, nil
}

func (service *Service) resourceByID(id string) (*models.Resource, error) {
	if err := service.readyStore(); err != nil {
		return nil, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("%w: resource ID required", ErrInvalidRequest)
	}
	resource, ok := service.store.GetResource(id)
	if !ok {
		return nil, ErrResourceNotFound
	}
	return resource, nil
}

func (service *Service) signResourceCert(domain string, validDays int) ([]byte, []byte, error) {
	if service.signer == nil {
		return nil, nil, fmt.Errorf("%w: PKI signer not initialized", ErrCertificateIssue)
	}
	role := strings.TrimSpace(service.pkiRole)
	if role == "" {
		return nil, nil, fmt.Errorf("%w: pki_role_resource is not configured", ErrCertificateIssue)
	}
	if validDays <= 0 {
		validDays = defaultCertValidity
	}
	csrPEM, keyPEM, err := certs.BuildResourceCSR(strings.TrimSpace(domain))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: build resource CSR: %v", ErrCertificateIssue, err)
	}
	certPEM, err := service.signer(csrPEM, validDays, role)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: vault sign resource cert: %v", ErrCertificateIssue, err)
	}
	return certPEM, keyPEM, nil
}

func (service *Service) readyStore() error {
	if service == nil || service.store == nil {
		return ErrServiceUnavailable
	}
	return nil
}

func (service *Service) clock() time.Time {
	if service != nil && service.now != nil {
		return service.now()
	}
	return time.Now()
}

func (service *Service) publishResourceEvent(resourceID, action, reason string) {
	if service == nil || service.publisher == nil {
		return
	}
	service.publisher.PublishCAEPEvent(events.TopicResourcesUpdated, map[string]string{
		"resource_id": resourceID,
		"app_id":      resourceID,
		"action":      action,
		"reason":      reason,
	})
}

func (service *Service) validateResourceScope(resource *models.Resource) error {
	if resource == nil {
		return fmt.Errorf("%w: resource is required", ErrInvalidRequest)
	}
	tenantID := strings.TrimSpace(resource.TenantID)
	gatewayID := strings.TrimSpace(resource.GatewayID)
	if tenantID == "" {
		return fmt.Errorf("%w: tenant_id is required", ErrInvalidRequest)
	}
	if gatewayID == "" {
		return fmt.Errorf("%w: gateway_id is required", ErrInvalidRequest)
	}
	tenant, ok := service.store.GetTenant(tenantID)
	if !ok || tenant == nil || !tenant.Enabled {
		return fmt.Errorf("%w: tenant not found or disabled", ErrInvalidRequest)
	}
	gateway, ok := service.store.GetGateway(gatewayID)
	if !ok || gateway == nil {
		return fmt.Errorf("%w: gateway not found", ErrInvalidRequest)
	}
	if strings.TrimSpace(gateway.TenantID) == "" || !strings.EqualFold(gateway.TenantID, tenantID) {
		return fmt.Errorf("%w: gateway does not belong to tenant", ErrInvalidRequest)
	}
	resource.TenantID = tenantID
	resource.GatewayID = gatewayID
	return nil
}

func validResourceType(resourceType string) bool {
	switch normalizeResourceType(resourceType) {
	case "ssh", "rdp", "web":
		return true
	default:
		return false
	}
}

func normalizeResourceType(resourceType string) string {
	return strings.ToLower(strings.TrimSpace(resourceType))
}

func generateClientCredentials() (string, string, error) {
	clientIDBytes := make([]byte, clientIDRandomBytes)
	if _, err := rand.Read(clientIDBytes); err != nil {
		return "", "", err
	}
	clientSecret, err := randomHex(clientSecretByteCount)
	if err != nil {
		return "", "", err
	}
	return "DI" + hex.EncodeToString(clientIDBytes), clientSecret, nil
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

func applyStringField(fields map[string]json.RawMessage, name string, target *string) {
	if value, ok := fields[name]; ok {
		_ = json.Unmarshal(value, target)
	}
}

func applyIntField(fields map[string]json.RawMessage, name string, target *int) {
	if value, ok := fields[name]; ok {
		_ = json.Unmarshal(value, target)
	}
}

func applyBoolField(fields map[string]json.RawMessage, name string, target *bool) {
	if value, ok := fields[name]; ok {
		_ = json.Unmarshal(value, target)
	}
}

func applyStringSliceField(fields map[string]json.RawMessage, name string, target *[]string) {
	if value, ok := fields[name]; ok {
		_ = json.Unmarshal(value, target)
	}
}

func applyStringMapField(fields map[string]json.RawMessage, name string, target *map[string]string) {
	if value, ok := fields[name]; ok {
		_ = json.Unmarshal(value, target)
	}
}
