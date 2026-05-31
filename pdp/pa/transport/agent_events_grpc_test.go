package transport

import (
	"testing"

	"pdp/pa/auth"
	"pdp/pa/events"
)

func TestAgentEventStreamFiltersSessionRevocationsToMatchingDeviceUser(t *testing.T) {
	service := &agentEventsGRPCService{}
	claims := &auth.CustomClaims{
		UserID:    "user-1",
		DeviceID:  "device-1",
		TenantID:  "tenant-1",
		SessionID: "agent-session-1",
	}

	payload, ok := service.agentEventForClaims(events.Event{
		Type: events.TopicSessionDeleted,
		Payload: map[string]string{
			"user_id":    "user-1",
			"device_id":  "device-1",
			"tenant_id":  "tenant-1",
			"session_id": "resource-session-1",
			"reason":     "device_posture_changed",
		},
	}, claims)
	if !ok {
		t.Fatal("matching session revocation was not delivered")
	}
	if payload["type"] != agentEventAccessRevoked || payload["session_id"] != "resource-session-1" {
		t.Fatalf("payload = %+v", payload)
	}

	if _, ok := service.agentEventForClaims(events.Event{
		Type: events.TopicSessionDeleted,
		Payload: map[string]string{
			"user_id":   "user-2",
			"device_id": "device-1",
			"tenant_id": "tenant-1",
		},
	}, claims); ok {
		t.Fatal("revocation for a different user was delivered")
	}
}

func TestAgentEventStreamPublishesCatalogInvalidationForTenantChanges(t *testing.T) {
	service := &agentEventsGRPCService{}
	claims := &auth.CustomClaims{
		UserID:    "user-1",
		DeviceID:  "device-1",
		TenantID:  "tenant-1",
		SessionID: "agent-session-1",
	}

	payload, ok := service.agentEventForClaims(events.Event{
		Type: events.TopicResourcesUpdated,
		Payload: map[string]string{
			"tenant_id":   "tenant-1",
			"resource_id": "res-1",
			"action":      "updated",
			"reason":      "resource_updated",
		},
	}, claims)
	if !ok {
		t.Fatal("tenant resource update was not delivered")
	}
	if payload["type"] != agentEventCatalogInvalidated || payload["resource_id"] != "res-1" {
		t.Fatalf("payload = %+v", payload)
	}

	if _, ok := service.agentEventForClaims(events.Event{
		Type: events.TopicResourcesUpdated,
		Payload: map[string]string{
			"tenant_id": "tenant-2",
		},
	}, claims); ok {
		t.Fatal("catalog invalidation for a different tenant was delivered")
	}
}
