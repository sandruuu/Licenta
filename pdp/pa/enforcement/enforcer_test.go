package enforcement

import (
	"testing"
	"time"

	"pdp/models"
	paadmin "pdp/pa"
	"pdp/pa/audit"
	"pdp/pa/events"
	"pdp/pa/sessions"
	"pdp/pe/evaluation"
	"pdp/store"
)

func TestHealthChangedRevokesSessionsThatNoLongerPassPolicy(t *testing.T) {
	policyAdmin, dataStore := newEnforcementTestPA(t)
	seedEnforcementScope(dataStore)
	now := time.Now()
	dataStore.SavePolicyRule(&models.PolicyRule{
		ID:      "pol-health",
		Name:    "Require healthy device",
		Enabled: true,
		Action:  "allow",
		Conditions: models.RuleConditions{
			DevicePosture: models.DevicePosturePolicyConditions{
				RequiredChecks: []string{"firewall"},
				RequiredStatus: "good",
			},
		},
		CreatedAt: now,
		UpdatedAt: now,
	})
	dataStore.SavePolicyAssignment(&models.PolicyAssignment{
		ID:        "assign-health",
		PolicyID:  "pol-health",
		TenantID:  "tenant-1",
		Level:     "organization",
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	})
	dataStore.SaveDeviceData(&models.DeviceDataReport{
		DeviceID:   "device-1",
		Hostname:   "host-1",
		OS:         "windows",
		ReportedAt: now,
		Checks: []models.HealthCheck{
			{Name: "firewall", Status: "warning"},
		},
	})
	dataStore.SaveSession(activeSession("sess-health", "device-1", "res-ssh", "gw-1", "tenant-1"))

	revoked := NewService(policyAdmin, nil).HandleEvent(events.Event{
		Type: events.TopicHealthChanged,
		Payload: map[string]string{
			"device_id": "device-1",
			"tenant_id": "tenant-1",
		},
	})

	if revoked != 1 {
		t.Fatalf("revoked = %d, want 1", revoked)
	}
	session, ok := dataStore.GetSession("sess-health")
	if !ok || !session.Revoked {
		t.Fatalf("session revoked = %v, found=%v", ok && session.Revoked, ok)
	}
}

func TestHealthChangedRevokesSessionsWithPostureChangeControl(t *testing.T) {
	policyAdmin, dataStore := newEnforcementTestPA(t)
	seedEnforcementScope(dataStore)
	session := activeSession("sess-posture-change", "device-1", "res-ssh", "gw-1", "tenant-1")
	session.RevokeOnPostureChange = true
	dataStore.SaveSession(session)

	revoked := NewService(policyAdmin, nil).HandleEvent(events.Event{
		Type: events.TopicHealthChanged,
		Payload: map[string]string{
			"device_id": "device-1",
			"tenant_id": "tenant-1",
		},
	})

	if revoked != 1 {
		t.Fatalf("revoked = %d, want 1", revoked)
	}
	assertRevoked(t, dataStore, "sess-posture-change", true)
}

func TestPolicyUpdatedRevokesDeniedSessionsWithinScope(t *testing.T) {
	policyAdmin, dataStore := newEnforcementTestPA(t)
	seedEnforcementScope(dataStore)
	now := time.Now()
	dataStore.SavePolicyRule(&models.PolicyRule{
		ID:         "pol-deny",
		Name:       "Deny SSH",
		Enabled:    true,
		Action:     "deny",
		Conditions: models.RuleConditions{},
		CreatedAt:  now,
		UpdatedAt:  now,
	})
	dataStore.SavePolicyAssignment(&models.PolicyAssignment{
		ID:         "assign-deny",
		PolicyID:   "pol-deny",
		TenantID:   "tenant-1",
		Level:      "resource",
		ResourceID: "res-ssh",
		Enabled:    true,
		CreatedAt:  now,
		UpdatedAt:  now,
	})
	dataStore.SaveSession(activeSession("sess-policy", "device-1", "res-ssh", "gw-1", "tenant-1"))
	dataStore.SaveSession(activeSession("sess-other-resource", "device-1", "res-web", "gw-1", "tenant-1"))

	revoked := NewService(policyAdmin, nil).HandleEvent(events.Event{
		Type: events.TopicPolicyUpdated,
		Payload: map[string]string{
			"tenant_id":   "tenant-1",
			"resource_id": "res-ssh",
		},
	})

	if revoked != 1 {
		t.Fatalf("revoked = %d, want 1", revoked)
	}
	assertRevoked(t, dataStore, "sess-policy", true)
	assertRevoked(t, dataStore, "sess-other-resource", false)
}

func TestResourceGatewayAndDeviceEventsRevokeScopedSessions(t *testing.T) {
	policyAdmin, dataStore := newEnforcementTestPA(t)
	seedEnforcementScope(dataStore)
	dataStore.SaveSession(activeSession("sess-resource", "device-1", "res-ssh", "gw-1", "tenant-1"))
	dataStore.SaveSession(activeSession("sess-gateway", "device-2", "res-web", "gw-1", "tenant-1"))
	dataStore.SaveSession(activeSession("sess-device", "device-3", "res-web", "gw-2", "tenant-1"))
	dataStore.SaveSession(activeSession("sess-other-tenant", "device-3", "res-web", "gw-2", "tenant-2"))

	service := NewService(policyAdmin, nil)
	if revoked := service.HandleEvent(events.Event{
		Type: events.TopicResourcesUpdated,
		Payload: map[string]string{
			"resource_id":      "res-ssh",
			"tenant_id":        "tenant-1",
			"action":           "updated",
			"revokes_sessions": "true",
		},
	}); revoked != 1 {
		t.Fatalf("resource revoked = %d, want 1", revoked)
	}
	if revoked := service.HandleEvent(events.Event{
		Type: events.TopicGatewayRevoked,
		Payload: map[string]string{
			"gateway_id": "gw-1",
			"tenant_id":  "tenant-1",
		},
	}); revoked != 1 {
		t.Fatalf("gateway revoked = %d, want 1", revoked)
	}
	if revoked := service.HandleEvent(events.Event{
		Type: events.TopicDeviceRevoked,
		Payload: map[string]string{
			"device_id": "device-3",
			"tenant_id": "tenant-1",
		},
	}); revoked != 1 {
		t.Fatalf("device revoked = %d, want 1", revoked)
	}

	assertRevoked(t, dataStore, "sess-resource", true)
	assertRevoked(t, dataStore, "sess-gateway", true)
	assertRevoked(t, dataStore, "sess-device", true)
	assertRevoked(t, dataStore, "sess-other-tenant", false)
}

func newEnforcementTestPA(t *testing.T) (*paadmin.PolicyAdministrator, *store.Store) {
	t.Helper()
	dataStore := store.New(t.TempDir())
	if err := dataStore.InitDB(); err != nil {
		t.Fatalf("InitDB() error = %v", err)
	}
	t.Cleanup(func() { _ = dataStore.Close() })
	policyAdmin := &paadmin.PolicyAdministrator{
		Engine:   evaluation.NewEngine(),
		Sessions: sessions.NewSessionManager(dataStore, time.Hour, 10),
		Audit:    audit.NewAuditLogger(dataStore),
		Store:    dataStore,
	}
	return policyAdmin, dataStore
}

func seedEnforcementScope(dataStore *store.Store) {
	now := time.Now()
	dataStore.SaveTenant(&models.Tenant{
		ID:        "tenant-1",
		Name:      "Tenant 1",
		Domain:    "tenant.test",
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	})
	dataStore.SaveTenant(&models.Tenant{
		ID:        "tenant-2",
		Name:      "Tenant 2",
		Domain:    "other.test",
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	})
	dataStore.SaveUser(&models.User{
		ID:        "user-1",
		Username:  "laura",
		Email:     "laura@tenant.test",
		Role:      "user",
		TenantID:  "tenant-1",
		CreatedAt: now,
		UpdatedAt: now,
	})
	dataStore.SaveGateway(&models.Gateway{
		ID:        "gw-1",
		TenantID:  "tenant-1",
		TenantIDs: []string{"tenant-1"},
		Name:      "Gateway 1",
		Status:    "enrolled",
		CreatedAt: now,
		UpdatedAt: now,
	})
	dataStore.SaveGateway(&models.Gateway{
		ID:        "gw-2",
		TenantID:  "tenant-1",
		TenantIDs: []string{"tenant-1"},
		Name:      "Gateway 2",
		Status:    "enrolled",
		CreatedAt: now,
		UpdatedAt: now,
	})
	dataStore.SaveResource(&models.Resource{
		ID:        "res-ssh",
		Name:      "SSH",
		Type:      "ssh",
		Host:      "ssh.internal",
		Port:      22,
		Enabled:   true,
		TenantID:  "tenant-1",
		GatewayID: "gw-1",
		CreatedAt: now,
		UpdatedAt: now,
	})
	dataStore.SaveResource(&models.Resource{
		ID:        "res-web",
		Name:      "Web",
		Type:      "web",
		Host:      "web.internal",
		Port:      443,
		Enabled:   true,
		TenantID:  "tenant-1",
		GatewayID: "gw-1",
		CreatedAt: now,
		UpdatedAt: now,
	})
}

func activeSession(id, deviceID, resourceID, gatewayID, tenantID string) *models.Session {
	now := time.Now()
	return &models.Session{
		ID:        id,
		UserID:    "user-1",
		Username:  "laura",
		DeviceID:  deviceID,
		SourceIP:  "192.0.2.10",
		Resource:  resourceID,
		GatewayID: gatewayID,
		Protocol:  "ssh",
		TenantID:  tenantID,
		CreatedAt: now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour),
	}
}

func assertRevoked(t *testing.T, dataStore *store.Store, sessionID string, want bool) {
	t.Helper()
	session, ok := dataStore.GetSession(sessionID)
	if !ok {
		t.Fatalf("session %s not found", sessionID)
	}
	if session.Revoked != want {
		t.Fatalf("session %s revoked = %v, want %v", sessionID, session.Revoked, want)
	}
}
