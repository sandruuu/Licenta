package resources

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"pdp/models"
	"pdp/pa/events"
	"pdp/store"
	"pdp/util"
)

var (
	ErrServiceUnavailable = errors.New("resource service is not available")
	ErrInvalidRequest     = errors.New("invalid resource request")
	ErrResourceNotFound   = errors.New("resource not found")
)

type EventPublisher interface {
	PublishCAEPEvent(eventType string, fields map[string]string)
}

type Service struct {
	store *store.Store
	now   func() time.Time

	publisher EventPublisher
}

func NewService(store *store.Store) *Service {
	return &Service{store: store, now: time.Now}
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
	resource.Name = strings.TrimSpace(resource.Name)
	if resource.Name == "" {
		return nil, fmt.Errorf("%w: Name is required", ErrInvalidRequest)
	}
	if strings.TrimSpace(resource.Type) == "" {
		return nil, fmt.Errorf("%w: Type is required", ErrInvalidRequest)
	}
	resource.Type = normalizeResourceType(resource.Type)
	if !validResourceType(resource.Type) {
		return nil, fmt.Errorf("%w: Type must be WEB, SSH, or RDP", ErrInvalidRequest)
	}
	if err := normalizeResource(&resource); err != nil {
		return nil, err
	}
	if err := service.validateResourceScope(&resource); err != nil {
		return nil, err
	}

	now := service.clock()
	resourceID, err := util.GenerateID("res")
	if err != nil {
		return nil, fmt.Errorf("generate resource ID: %w", err)
	}

	resource.ID = resourceID
	resource.CreatedAt = now
	resource.UpdatedAt = now
	resource.Enabled = true

	if err := service.store.SaveResource(&resource); err != nil {
		return nil, fmt.Errorf("save resource: %w", err)
	}
	service.publishResourceEvent(&resource, "created", "resource_created", false)
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
	applyIntField(fields, "external_port", &updated.ExternalPort)
	applyIntField(fields, "internal_port", &updated.InternalPort)
	applyStringField(fields, "external_url", &updated.ExternalURL)
	applyBoolField(fields, "enabled", &updated.Enabled)
	applyStringSliceField(fields, "tags", &updated.Tags)
	applyStringMapField(fields, "metadata", &updated.Metadata)
	applyStringField(fields, "organization_id", &updated.OrganizationID)
	applyStringField(fields, "gateway_id", &updated.GatewayID)

	if !validResourceType(updated.Type) {
		return nil, fmt.Errorf("%w: Type must be WEB, SSH, or RDP", ErrInvalidRequest)
	}
	if err := normalizeResource(&updated); err != nil {
		return nil, err
	}
	if err := service.validateResourceScope(&updated); err != nil {
		return nil, err
	}

	revokesSessions := resourceUpdateRevokesSessions(existing, &updated)
	if err := service.store.SaveResource(&updated); err != nil {
		return nil, fmt.Errorf("save resource: %w", err)
	}
	service.publishResourceEvent(&updated, "updated", "resource_updated", revokesSessions)
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
	existing, _ := service.store.GetResource(id)
	if !service.store.DeleteResource(id) {
		return ErrResourceNotFound
	}
	if existing == nil {
		existing = &models.Resource{ID: id}
	}
	service.publishResourceEvent(existing, "deleted", "resource_deleted", true)
	return nil
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

func (service *Service) publishResourceEvent(resource *models.Resource, action, reason string, revokesSessions bool) {
	if service == nil || service.publisher == nil {
		return
	}
	if resource == nil {
		return
	}
	service.publisher.PublishCAEPEvent(events.TopicResourcesUpdated, map[string]string{
		"resource_id":      resource.ID,
		"app_id":           resource.ID,
		"organization_id":  resource.OrganizationID,
		"gateway_id":       resource.GatewayID,
		"action":           action,
		"reason":           reason,
		"revokes_sessions": strconv.FormatBool(revokesSessions),
	})
}

func resourceUpdateRevokesSessions(existing, updated *models.Resource) bool {
	if existing == nil || updated == nil {
		return true
	}
	if existing.Enabled && !updated.Enabled {
		return true
	}
	return strings.TrimSpace(existing.Type) != strings.TrimSpace(updated.Type) ||
		strings.TrimSpace(existing.Host) != strings.TrimSpace(updated.Host) ||
		existing.ExternalPort != updated.ExternalPort ||
		existing.InternalPort != updated.InternalPort ||
		strings.TrimSpace(existing.ExternalURL) != strings.TrimSpace(updated.ExternalURL) ||
		strings.TrimSpace(existing.OrganizationID) != strings.TrimSpace(updated.OrganizationID) ||
		strings.TrimSpace(existing.GatewayID) != strings.TrimSpace(updated.GatewayID)
}

func (service *Service) validateResourceScope(resource *models.Resource) error {
	if resource == nil {
		return fmt.Errorf("%w: resource is required", ErrInvalidRequest)
	}
	organizationID := strings.TrimSpace(resource.OrganizationID)
	gatewayID := strings.TrimSpace(resource.GatewayID)
	if organizationID == "" {
		return fmt.Errorf("%w: organization_id is required", ErrInvalidRequest)
	}
	if gatewayID == "" {
		return fmt.Errorf("%w: gateway_id is required", ErrInvalidRequest)
	}
	organization, ok := service.store.GetOrganization(organizationID)
	if !ok || organization == nil || !organization.Enabled {
		return fmt.Errorf("%w: organization not found or disabled", ErrInvalidRequest)
	}
	gateway, ok := service.store.GetGateway(gatewayID)
	if !ok || gateway == nil {
		return fmt.Errorf("%w: gateway not found", ErrInvalidRequest)
	}
	if strings.TrimSpace(gateway.OrganizationID) == "" || !strings.EqualFold(gateway.OrganizationID, organizationID) {
		return fmt.Errorf("%w: gateway does not belong to organization", ErrInvalidRequest)
	}
	resource.OrganizationID = organizationID
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

func normalizeResource(resource *models.Resource) error {
	if resource == nil {
		return nil
	}
	resource.Type = normalizeResourceType(resource.Type)
	resource.Name = strings.TrimSpace(resource.Name)
	if resource.Name == "" {
		return fmt.Errorf("%w: Name is required", ErrInvalidRequest)
	}
	if !validResourcePort(resource.ExternalPort) {
		return fmt.Errorf("%w: External Port must be between 1 and 65535", ErrInvalidRequest)
	}
	if !validResourcePort(resource.InternalPort) {
		return fmt.Errorf("%w: Internal Port must be between 1 and 65535", ErrInvalidRequest)
	}
	internalHost, err := normalizeInternalHost(resource.Host)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidRequest, err.Error())
	}
	externalHost, err := validateExternalHost(resource.ExternalURL)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidRequest, err.Error())
	}
	resource.Host = internalHost
	resource.ExternalURL = externalHost
	return nil
}

func normalizeInternalHost(value string) (string, error) {
	host := strings.ToLower(strings.TrimSpace(value))
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "", errors.New("internal host is required")
	}
	if looksLikeIPv4(host) {
		if ip := net.ParseIP(host); ip == nil || ip.To4() == nil {
			return "", errors.New("internal host must be a valid IPv4 address or DNS hostname")
		}
		return host, nil
	}
	if !validDNSName(host, false) {
		return "", errors.New("internal host must be a valid IPv4 address or DNS hostname")
	}
	return host, nil
}

func validateExternalHost(value string) (string, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return "", errors.New("external host is required")
	}
	host := raw
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Hostname() == "" {
			return "", errors.New("external host must be a valid HTTP/HTTPS URL or DNS hostname")
		}
		if parsed.Port() != "" {
			return "", errors.New("external host cannot include a port. Use external port instead")
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return "", errors.New("external host URL must use HTTP or HTTPS")
		}
		host = parsed.Hostname()
	} else if strings.ContainsAny(raw, "/?#") || strings.Contains(raw, ":") {
		return "", errors.New("external host must be a valid HTTP/HTTPS URL or DNS hostname")
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if net.ParseIP(host) != nil || looksLikeIPv4(host) {
		return "", errors.New("external host must be a valid DNS hostname")
	}
	if !validDNSName(host, true) {
		return "", errors.New("external host must be a valid DNS hostname")
	}
	return raw, nil
}

func looksLikeIPv4(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && char != '.' {
			return false
		}
	}
	return strings.Contains(value, ".") || value[0] >= '0' && value[0] <= '9'
}

func validDNSName(value string, requireDot bool) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	if strings.Contains(value, "..") {
		return false
	}
	if requireDot && !strings.Contains(value, ".") {
		return false
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, char := range label {
			if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func validResourcePort(port int) bool {
	return port > 0 && port <= 65535
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
