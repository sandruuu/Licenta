package enforcement

import (
	"testing"
	"time"

	"pdp/internal/testdb"
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
		ID:             "assign-health",
		PolicyID:       "pol-health",
		OrganizationID: "organization-1",
		Level:          "organization",
		Enabled:        true,
		CreatedAt:      now,
		UpdatedAt:      now,
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
	dataStore.SaveSession(activeSession("sess-health", "device-1", "res-ssh", "gw-1", "organization-1"))

	revoked := NewService(policyAdmin, nil).HandleEvent(events.Event{
		Type: events.TopicHealthChanged,
		Payload: map[string]string{
			"device_id":       "device-1",
			"organization_id": "organization-1",
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
	session := activeSession("sess-posture-change", "device-1", "res-ssh", "gw-1", "organization-1")
	session.RevokeOnPostureChange = true
	dataStore.SaveSession(session)

	revoked := NewService(policyAdmin, nil).HandleEvent(events.Event{
		Type: events.TopicHealthChanged,
		Payload: map[string]string{
			"device_id":       "device-1",
			"organization_id": "organization-1",
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
		ID:             "assign-deny",
		PolicyID:       "pol-deny",
		OrganizationID: "organization-1",
		Level:          "resource",
		ResourceID:     "res-ssh",
		Enabled:        true,
		CreatedAt:      now,
		UpdatedAt:      now,
	})
	dataStore.SaveSession(activeSession("sess-policy", "device-1", "res-ssh", "gw-1", "organization-1"))
	dataStore.SaveSession(activeSession("sess-other-resource", "device-1", "res-web", "gw-1", "organization-1"))

	revoked := NewService(policyAdmin, nil).HandleEvent(events.Event{
		Type: events.TopicPolicyUpdated,
		Payload: map[string]string{
			"organization_id": "organization-1",
			"resource_id":     "res-ssh",
		},
	})

	if revoked != 1 {
		t.Fatalf("revoked = %d, want 1", revoked)
	}
	assertRevoked(t, dataStore, "sess-policy", true)
	assertRevoked(t, dataStore, "sess-other-resource", false)
}

func TestPolicyUpdatedKeepsSessionWithSatisfiedStepUp(t *testing.T) {
	policyAdmin, dataStore := newEnforcementTestPA(t)
	seedEnforcementScope(dataStore)
	now := time.Now()
	dataStore.SavePolicyRule(&models.PolicyRule{
		ID:      "pol-step-up",
		Name:    "Require MFA",
		Enabled: true,
		Action:  models.DecisionStepUpRequired,
		Conditions: models.RuleConditions{
			Authentication: models.AuthenticationPolicyConditions{
				Policy:        models.AuthenticationPolicyEnforceMFA,
				StepUpMethods: []string{"totp"},
			},
		},
		CreatedAt: now,
		UpdatedAt: now,
	})
	dataStore.SavePolicyAssignment(&models.PolicyAssignment{
		ID:             "assign-step-up",
		PolicyID:       "pol-step-up",
		OrganizationID: "organization-1",
		Level:          "resource",
		ResourceID:     "res-ssh",
		Enabled:        true,
		CreatedAt:      now,
		UpdatedAt:      now,
	})
	session := activeSession("sess-step-up", "device-1", "res-ssh", "gw-1", "organization-1")
	session.StepUpACR = models.DefaultStepUpACR
	session.StepUpMethod = "totp"
	session.StepUpStrength = models.StepUpStrengthOTP
	session.StepUpVerifiedAt = now.Add(-time.Minute)
	session.StepUpExpiresAt = now.Add(9 * time.Minute)
	dataStore.SaveSession(session)

	revoked := NewService(policyAdmin, nil).HandleEvent(events.Event{
		Type: events.TopicPolicyUpdated,
		Payload: map[string]string{
			"organization_id": "organization-1",
			"resource_id":     "res-ssh",
		},
	})

	if revoked != 0 {
		t.Fatalf("revoked = %d, want 0", revoked)
	}
	assertRevoked(t, dataStore, "sess-step-up", false)
}

func TestSessionStepUpAuthContextCarriesWebAuthnProof(t *testing.T) {
	now := time.Now()
	session := &models.Session{
		StepUpACR:        models.DefaultStepUpACR,
		StepUpMethod:     "webauthn",
		StepUpStrength:   models.StepUpStrengthHardwareKey,
		StepUpAAGUID:     "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		StepUpAttachment: "cross_platform",
		StepUpVerifiedAt: now.Add(-time.Minute),
		StepUpExpiresAt:  now.Add(9 * time.Minute),
	}

	auth := sessionStepUpAuthContext(session)
	if auth.ACR != models.DefaultStepUpACR {
		t.Fatalf("ACR = %q, want %q", auth.ACR, models.DefaultStepUpACR)
	}
	if len(auth.AMR) != 1 || auth.AMR[0] != "webauthn" {
		t.Fatalf("AMR = %+v, want [webauthn]", auth.AMR)
	}
	if auth.StepUpMethod != "webauthn" || auth.StepUpStrength != models.StepUpStrengthHardwareKey {
		t.Fatalf("step-up method/strength = %q/%q", auth.StepUpMethod, auth.StepUpStrength)
	}
	if auth.StepUpAAGUID != "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" {
		t.Fatalf("AAGUID = %q", auth.StepUpAAGUID)
	}
	if auth.StepUpAttachment != "cross_platform" {
		t.Fatalf("attachment = %q", auth.StepUpAttachment)
	}
	if !auth.StepUpVerifiedAt.Equal(session.StepUpVerifiedAt) || !auth.StepUpExpiresAt.Equal(session.StepUpExpiresAt) {
		t.Fatalf("step-up times were not preserved")
	}
}

func TestResourceGatewayAndDeviceEventsRevokeScopedSessions(t *testing.T) {
	policyAdmin, dataStore := newEnforcementTestPA(t)
	seedEnforcementScope(dataStore)
	dataStore.SaveSession(activeSession("sess-resource", "device-1", "res-ssh", "gw-1", "organization-1"))
	dataStore.SaveSession(activeSession("sess-gateway", "device-2", "res-web", "gw-1", "organization-1"))
	dataStore.SaveSession(activeSession("sess-device", "device-3", "res-web", "gw-2", "organization-1"))
	dataStore.SaveSession(activeSession("sess-other-organization", "device-3", "res-web", "gw-2", "organization-2"))

	service := NewService(policyAdmin, nil)
	if revoked := service.HandleEvent(events.Event{
		Type: events.TopicResourcesUpdated,
		Payload: map[string]string{
			"resource_id":      "res-ssh",
			"organization_id":  "organization-1",
			"action":           "updated",
			"revokes_sessions": "true",
		},
	}); revoked != 1 {
		t.Fatalf("resource revoked = %d, want 1", revoked)
	}
	if revoked := service.HandleEvent(events.Event{
		Type: events.TopicGatewayRevoked,
		Payload: map[string]string{
			"gateway_id":      "gw-1",
			"organization_id": "organization-1",
		},
	}); revoked != 1 {
		t.Fatalf("gateway revoked = %d, want 1", revoked)
	}
	if revoked := service.HandleEvent(events.Event{
		Type: events.TopicDeviceRevoked,
		Payload: map[string]string{
			"device_id":       "device-3",
			"organization_id": "organization-1",
		},
	}); revoked != 1 {
		t.Fatalf("device revoked = %d, want 1", revoked)
	}

	assertRevoked(t, dataStore, "sess-resource", true)
	assertRevoked(t, dataStore, "sess-gateway", true)
	assertRevoked(t, dataStore, "sess-device", true)
	assertRevoked(t, dataStore, "sess-other-organization", false)
}

func newEnforcementTestPA(t *testing.T) (*paadmin.PolicyAdministrator, *store.Store) {
	t.Helper()
	dataStore := testdb.NewStore(t)
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
	dataStore.SaveOrganization(&models.Organization{
		ID:        "organization-1",
		Name:      "Organization 1",
		Domain:    "organization.test",
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	})
	dataStore.SaveOrganization(&models.Organization{
		ID:        "organization-2",
		Name:      "Organization 2",
		Domain:    "other.test",
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	})
	dataStore.SaveUser(&models.User{
		ID:             "user-1",
		Username:       "laura",
		Email:          "laura@organization.test",
		Role:           "user",
		OrganizationID: "organization-1",
		CreatedAt:      now,
		UpdatedAt:      now,
	})
	dataStore.SaveGateway(&models.Gateway{
		ID:              "gw-1",
		OrganizationID:  "organization-1",
		OrganizationIDs: []string{"organization-1"},
		Name:            "Gateway 1",
		Status:          "enrolled",
		CreatedAt:       now,
		UpdatedAt:       now,
	})
	dataStore.SaveGateway(&models.Gateway{
		ID:              "gw-2",
		OrganizationID:  "organization-1",
		OrganizationIDs: []string{"organization-1"},
		Name:            "Gateway 2",
		Status:          "enrolled",
		CreatedAt:       now,
		UpdatedAt:       now,
	})
	dataStore.SaveResource(&models.Resource{
		ID:             "res-ssh",
		Name:           "SSH",
		Type:           "ssh",
		Host:           "ssh.internal",
		ExternalPort:   22,
		InternalPort:   22,
		Enabled:        true,
		OrganizationID: "organization-1",
		GatewayID:      "gw-1",
		CreatedAt:      now,
		UpdatedAt:      now,
	})
	dataStore.SaveResource(&models.Resource{
		ID:             "res-web",
		Name:           "Web",
		Type:           "web",
		Host:           "web.internal",
		ExternalPort:   443,
		InternalPort:   443,
		Enabled:        true,
		OrganizationID: "organization-1",
		GatewayID:      "gw-1",
		CreatedAt:      now,
		UpdatedAt:      now,
	})
}

func activeSession(id, deviceID, resourceID, gatewayID, organizationID string) *models.Session {
	now := time.Now()
	return &models.Session{
		ID:             id,
		UserID:         "user-1",
		Username:       "laura",
		DeviceID:       deviceID,
		SourceIP:       "192.0.2.10",
		Resource:       resourceID,
		GatewayID:      gatewayID,
		Protocol:       "ssh",
		OrganizationID: organizationID,
		CreatedAt:      now.Add(-time.Minute),
		ExpiresAt:      now.Add(time.Hour),
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
