package resources

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"pdp/models"
	"pdp/store"
)

func TestServiceCreateResourceCreatesProtectedResourceAndPublishesEvent(t *testing.T) {
	dataStore := newResourceTestStore(t)
	seedResourceScope(dataStore)
	publisher := &testResourcePublisher{}
	fixedNow := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	service := NewService(dataStore)
	service.SetEventPublisher(publisher)
	service.now = func() time.Time { return fixedNow }

	resource, err := service.CreateResource(models.Resource{
		TenantID:  testTenantID,
		GatewayID: testGatewayID,
		Name:      "SSH Admin",
		Type:      "ssh",
		Host:      "ssh.internal.test",
		Port:      22,
		AllowedRoles: []string{
			"admin",
		},
		RequireMFA: true,
	})
	if err != nil {
		t.Fatalf("CreateResource returned error: %v", err)
	}
	if !strings.HasPrefix(resource.ID, "res_") {
		t.Fatalf("resource ID = %q, want res_ prefix", resource.ID)
	}
	if resource.ClientID != "" || resource.ClientSecret != "" {
		t.Fatalf("protected resource should not receive OIDC credentials: client_id=%q secret=%q", resource.ClientID, resource.ClientSecret)
	}
	if !resource.Enabled {
		t.Fatalf("resource should be enabled by default: %+v", resource)
	}
	if len(resource.AllowedRoles) != 0 {
		t.Fatalf("resource creation should not persist allowed_roles: %+v", resource.AllowedRoles)
	}
	if resource.RequireMFA {
		t.Fatalf("resource creation should not persist require_mfa")
	}
	if len(publisher.events) != 1 || publisher.events[0].fields["action"] != "created" || publisher.events[0].fields["resource_id"] != resource.ID {
		t.Fatalf("resource created event mismatch: %+v", publisher.events)
	}
	saved, found := dataStore.GetResource(resource.ID)
	if !found || saved.Name != resource.Name || saved.ClientID != "" || saved.ClientSecret != "" {
		t.Fatalf("resource was not persisted correctly: found=%v saved=%+v", found, saved)
	}
	if len(saved.AllowedRoles) != 0 {
		t.Fatalf("saved resource should not contain allowed_roles: %+v", saved.AllowedRoles)
	}
	if saved.RequireMFA {
		t.Fatalf("saved resource should not contain require_mfa")
	}
}

func TestServiceCreateResourceValidatesRequest(t *testing.T) {
	dataStore := newResourceTestStore(t)
	seedResourceScope(dataStore)
	service := NewService(dataStore)

	_, err := service.CreateResource(models.Resource{Name: "Missing Type"})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("missing type error = %v, want ErrInvalidRequest", err)
	}

	_, err = service.CreateResource(models.Resource{Name: "Bad", Type: "database"})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid type error = %v, want ErrInvalidRequest", err)
	}

	_, err = service.CreateResource(models.Resource{Name: "No Scope", Type: "ssh"})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("missing scope error = %v, want ErrInvalidRequest", err)
	}
}

func TestServiceListResourcesHidesLegacyClientCredentials(t *testing.T) {
	dataStore := newResourceTestStore(t)
	service := NewService(dataStore)
	dataStore.SaveResource(&models.Resource{
		ID:           "res-1",
		Name:         "Legacy App",
		Type:         "web",
		ClientID:     "DIoldclientid123456",
		ClientSecret: "old-secret",
		Enabled:      true,
	})

	resources, err := service.ListResources()
	if err != nil {
		t.Fatalf("ListResources returned error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("resource count = %d, want 1", len(resources))
	}
	if resources[0].ClientID != "" || resources[0].ClientSecret != "" {
		t.Fatalf("legacy credentials should be hidden: client_id=%q secret=%q", resources[0].ClientID, resources[0].ClientSecret)
	}
}

func TestServiceUpdateResourcePatchesFieldsAndPublishesEvent(t *testing.T) {
	dataStore := newResourceTestStore(t)
	seedResourceScope(dataStore)
	publisher := &testResourcePublisher{}
	fixedNow := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	service := NewService(dataStore)
	service.SetEventPublisher(publisher)
	service.now = func() time.Time { return fixedNow }
	dataStore.SaveResource(&models.Resource{ID: "res-1", TenantID: testTenantID, GatewayID: testGatewayID, Name: "Old", Type: "ssh", Host: "old.internal", Port: 22, Enabled: true, CreatedAt: fixedNow.Add(-time.Hour), UpdatedAt: fixedNow.Add(-time.Hour)})

	fields := map[string]json.RawMessage{
		"name":          json.RawMessage(`"New"`),
		"port":          json.RawMessage(`2222`),
		"enabled":       json.RawMessage(`false`),
		"tags":          json.RawMessage(`["prod","ssh"]`),
		"metadata":      json.RawMessage(`{"owner":"ops"}`),
		"allowed_roles": json.RawMessage(`["admin"]`),
		"require_mfa":   json.RawMessage(`true`),
	}
	updated, err := service.UpdateResource("res-1", fields)
	if err != nil {
		t.Fatalf("UpdateResource returned error: %v", err)
	}
	if updated.Name != "New" || updated.Port != 2222 || updated.Enabled || len(updated.Tags) != 2 || updated.Metadata["owner"] != "ops" {
		t.Fatalf("resource fields not patched correctly: %+v", updated)
	}
	if len(updated.AllowedRoles) != 0 || updated.RequireMFA {
		t.Fatalf("legacy access fields should be ignored: %+v", updated)
	}
	if len(publisher.events) != 1 || publisher.events[0].fields["action"] != "updated" {
		t.Fatalf("resource updated event mismatch: %+v", publisher.events)
	}
}

func TestServiceDeleteResourcePublishesEvent(t *testing.T) {
	dataStore := newResourceTestStore(t)
	publisher := &testResourcePublisher{}
	fixedNow := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	service := NewService(dataStore)
	service.SetEventPublisher(publisher)
	service.now = func() time.Time { return fixedNow }
	dataStore.SaveResource(&models.Resource{ID: "res-1", Name: "Portal", Type: "web", Host: "portal.internal.test", CreatedAt: fixedNow.Add(-time.Hour), UpdatedAt: fixedNow.Add(-time.Hour)})

	if err := service.DeleteResource("res-1"); err != nil {
		t.Fatalf("DeleteResource returned error: %v", err)
	}
	if _, found := dataStore.GetResource("res-1"); found {
		t.Fatalf("deleted resource still exists")
	}
	if len(publisher.events) != 1 || publisher.events[0].fields["action"] != "deleted" {
		t.Fatalf("resource deleted event mismatch: %+v", publisher.events)
	}
}

func newResourceTestStore(t *testing.T) *store.Store {
	t.Helper()
	dataStore := store.New(t.TempDir())
	if err := dataStore.InitDB(); err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { _ = dataStore.Close() })
	return dataStore
}

const (
	testTenantID  = "tenant-1"
	testGatewayID = "gw-1"
)

func seedResourceScope(dataStore *store.Store) {
	now := time.Now()
	dataStore.SaveTenant(&models.Tenant{
		ID:        testTenantID,
		Name:      "Test Tenant",
		Domain:    "example.test",
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	})
	dataStore.SaveGateway(&models.Gateway{
		ID:        testGatewayID,
		TenantID:  testTenantID,
		TenantIDs: []string{testTenantID},
		Name:      "Test Gateway",
		FQDN:      "gateway.example.test",
		Status:    "enrolled",
		CreatedAt: now,
		UpdatedAt: now,
	})
}

type testResourcePublisher struct {
	events []testResourceEvent
}

type testResourceEvent struct {
	eventType string
	fields    map[string]string
}

func (publisher *testResourcePublisher) PublishCAEPEvent(eventType string, fields map[string]string) {
	publisher.events = append(publisher.events, testResourceEvent{eventType: eventType, fields: fields})
}
