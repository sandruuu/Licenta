package resources

import (
	"encoding/json"
	"errors"
	"fmt"
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
	resources := service.store.ListResources()
	clearResourceClientFields(resources...)
	return resources, nil
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
	if err := normalizeWebResource(&resource); err != nil {
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
	resource.ClientID = ""
	resource.ClientSecret = ""
	resource.AllowedRoles = nil

	service.store.SaveResource(&resource)
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
	applyIntField(fields, "port", &updated.Port)
	applyStringField(fields, "external_url", &updated.ExternalURL)
	applyBoolField(fields, "enabled", &updated.Enabled)
	applyStringSliceField(fields, "tags", &updated.Tags)
	applyStringMapField(fields, "metadata", &updated.Metadata)
	applyStringField(fields, "tenant_id", &updated.TenantID)
	applyStringField(fields, "gateway_id", &updated.GatewayID)

	if !validResourceType(updated.Type) {
		return nil, fmt.Errorf("%w: type must be ssh, rdp, or web", ErrInvalidRequest)
	}
	if err := normalizeWebResource(&updated); err != nil {
		return nil, err
	}
	if err := service.validateResourceScope(&updated); err != nil {
		return nil, err
	}

	revokesSessions := resourceUpdateRevokesSessions(existing, &updated)
	service.store.SaveResource(&updated)
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
	clearResourceClientFields(resource)
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
		"tenant_id":        resource.TenantID,
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
		existing.Port != updated.Port ||
		strings.TrimSpace(existing.ExternalURL) != strings.TrimSpace(updated.ExternalURL) ||
		strings.TrimSpace(existing.TenantID) != strings.TrimSpace(updated.TenantID) ||
		strings.TrimSpace(existing.GatewayID) != strings.TrimSpace(updated.GatewayID)
}

func (service *Service) validateResourceScope(resource *models.Resource) error {
	if resource == nil {
		return fmt.Errorf("%w: resource is required", ErrInvalidRequest)
	}
	tenantID := strings.TrimSpace(resource.TenantID)
	gatewayID := strings.TrimSpace(resource.GatewayID)
	if tenantID == "" {
		return fmt.Errorf("%w: organization_id is required", ErrInvalidRequest)
	}
	if gatewayID == "" {
		return fmt.Errorf("%w: gateway_id is required", ErrInvalidRequest)
	}
	tenant, ok := service.store.GetTenant(tenantID)
	if !ok || tenant == nil || !tenant.Enabled {
		return fmt.Errorf("%w: organization not found or disabled", ErrInvalidRequest)
	}
	gateway, ok := service.store.GetGateway(gatewayID)
	if !ok || gateway == nil {
		return fmt.Errorf("%w: gateway not found", ErrInvalidRequest)
	}
	if strings.TrimSpace(gateway.TenantID) == "" || !strings.EqualFold(gateway.TenantID, tenantID) {
		return fmt.Errorf("%w: gateway does not belong to organization", ErrInvalidRequest)
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

func normalizeWebResource(resource *models.Resource) error {
	if resource == nil || normalizeResourceType(resource.Type) != "web" {
		return nil
	}
	if resource.Port <= 0 {
		resource.Port = 443
	}
	externalURL := strings.TrimSpace(resource.ExternalURL)
	if externalURL == "" {
		return nil
	}
	parsed, err := url.Parse(externalURL)
	if err != nil || strings.TrimSpace(parsed.Scheme) == "" {
		return fmt.Errorf("%w: web external_url must be a valid HTTPS URL", ErrInvalidRequest)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return fmt.Errorf("%w: web resources must use HTTPS external_url", ErrInvalidRequest)
	}
	return nil
}

func clearResourceClientFields(resources ...*models.Resource) {
	for _, resource := range resources {
		if resource == nil {
			continue
		}
		resource.ClientID = ""
		resource.ClientSecret = ""
	}
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
