package resources

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"pdp/internal/testdb"
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
		OrganizationID: testOrganizationID,
		GatewayID:      testGatewayID,
		Name:           "SSH Admin",
		Type:           "ssh",
		Host:           "ssh.internal.test",
		Port:           22,
	})
	if err != nil {
		t.Fatalf("CreateResource returned error: %v", err)
	}
	if !strings.HasPrefix(resource.ID, "res_") {
		t.Fatalf("resource ID = %q, want res_ prefix", resource.ID)
	}
	if !resource.Enabled {
		t.Fatalf("resource should be enabled by default: %+v", resource)
	}
	if len(publisher.events) != 1 || publisher.events[0].fields["action"] != "created" || publisher.events[0].fields["resource_id"] != resource.ID {
		t.Fatalf("resource created event mismatch: %+v", publisher.events)
	}
	saved, found := dataStore.GetResource(resource.ID)
	if !found || saved.Name != resource.Name {
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

func TestServiceCreateResourceRequiresHTTPSForWebResources(t *testing.T) {
	dataStore := newResourceTestStore(t)
	seedResourceScope(dataStore)
	service := NewService(dataStore)

	_, err := service.CreateResource(models.Resource{
		OrganizationID: testOrganizationID,
		GatewayID:      testGatewayID,
		Name:           "Portal",
		Type:           "web",
		Host:           "web-app",
		ExternalURL:    "http://web-app.trustcloud.test",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("http web resource error = %v, want ErrInvalidRequest", err)
	}

	resource, err := service.CreateResource(models.Resource{
		OrganizationID: testOrganizationID,
		GatewayID:      testGatewayID,
		Name:           "Portal",
		Type:           "web",
		Host:           "web-app",
		ExternalURL:    "https://web-app.trustcloud.test",
	})
	if err != nil {
		t.Fatalf("CreateResource returned error: %v", err)
	}
	if resource.Port != 443 {
		t.Fatalf("default web resource port = %d, want 443", resource.Port)
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
	dataStore.SaveResource(&models.Resource{ID: "res-1", OrganizationID: testOrganizationID, GatewayID: testGatewayID, Name: "Old", Type: "ssh", Host: "old.internal", Port: 22, Enabled: true, CreatedAt: fixedNow.Add(-time.Hour), UpdatedAt: fixedNow.Add(-time.Hour)})

	fields := map[string]json.RawMessage{
		"name":     json.RawMessage(`"New"`),
		"port":     json.RawMessage(`2222`),
		"enabled":  json.RawMessage(`false`),
		"tags":     json.RawMessage(`["prod","ssh"]`),
		"metadata": json.RawMessage(`{"owner":"ops"}`),
	}
	updated, err := service.UpdateResource("res-1", fields)
	if err != nil {
		t.Fatalf("UpdateResource returned error: %v", err)
	}
	if updated.Name != "New" || updated.Port != 2222 || updated.Enabled || len(updated.Tags) != 2 || updated.Metadata["owner"] != "ops" {
		t.Fatalf("resource fields not patched correctly: %+v", updated)
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
	return testdb.NewStore(t)
}

const (
	testOrganizationID = "organization-1"
	testGatewayID      = "gw-1"
)

func seedResourceScope(dataStore *store.Store) {
	now := time.Now()
	dataStore.SaveOrganization(&models.Organization{
		ID:        testOrganizationID,
		Name:      "Test Organization",
		Domain:    "example.test",
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	})
	dataStore.SaveGateway(&models.Gateway{
		ID:              testGatewayID,
		OrganizationID:  testOrganizationID,
		OrganizationIDs: []string{testOrganizationID},
		Name:            "Test Gateway",
		FQDN:            "gateway.example.test",
		Status:          "enrolled",
		CreatedAt:       now,
		UpdatedAt:       now,
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
