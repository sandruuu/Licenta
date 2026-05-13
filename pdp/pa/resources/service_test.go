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

func TestServiceCreateResourceGeneratesCredentialsAndPublishesEvent(t *testing.T) {
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
	})
	if err != nil {
		t.Fatalf("CreateResource returned error: %v", err)
	}
	if !strings.HasPrefix(resource.ID, "res_") {
		t.Fatalf("resource ID = %q, want res_ prefix", resource.ID)
	}
	if !strings.HasPrefix(resource.ClientID, "DI") || len(resource.ClientID) != 20 || len(resource.ClientSecret) != 40 {
		t.Fatalf("credentials not generated correctly: client_id=%q secret_len=%d", resource.ClientID, len(resource.ClientSecret))
	}
	if !resource.Enabled {
		t.Fatalf("resource should be enabled by default: %+v", resource)
	}
	if len(publisher.events) != 1 || publisher.events[0].fields["action"] != "created" || publisher.events[0].fields["resource_id"] != resource.ID {
		t.Fatalf("resource created event mismatch: %+v", publisher.events)
	}
	saved, found := dataStore.GetResource(resource.ID)
	if !found || saved.ClientID != resource.ClientID {
		t.Fatalf("resource was not persisted correctly: found=%v saved=%+v", found, saved)
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
	if updated.Name != "New" || updated.Port != 2222 || updated.Enabled || len(updated.Tags) != 2 || updated.Metadata["owner"] != "ops" || !updated.RequireMFA {
		t.Fatalf("resource fields not patched correctly: %+v", updated)
	}
	if len(publisher.events) != 1 || publisher.events[0].fields["action"] != "updated" {
		t.Fatalf("resource updated event mismatch: %+v", publisher.events)
	}
}

func TestServiceRegenerateSecretPreservesClientID(t *testing.T) {
	dataStore := newResourceTestStore(t)
	fixedNow := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	service := NewService(dataStore)
	service.now = func() time.Time { return fixedNow }
	dataStore.SaveResource(&models.Resource{ID: "res-1", Name: "App", Type: "web", ClientID: "DIoldclientid123456", ClientSecret: "old-secret"})

	resource, err := service.RegenerateSecret("res-1")
	if err != nil {
		t.Fatalf("RegenerateSecret returned error: %v", err)
	}
	if resource.ClientID != "DIoldclientid123456" || resource.ClientSecret == "old-secret" || len(resource.ClientSecret) != 40 {
		t.Fatalf("secret regeneration mismatch: client_id=%q secret=%q", resource.ClientID, resource.ClientSecret)
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
