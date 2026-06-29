package transport

import (
	"context"
	"strings"
	"testing"
	"time"

	"pdp/models"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestAgentSessionStartSessionRequiresRenewalManagedProtocol(t *testing.T) {
	server, dataStore := newDeviceAPITestServer(t)

	deviceCertPEM, deviceCert := newDeviceAPICertificate(t, "device-1", time.Now().Add(time.Hour))
	enrollment := &models.DeviceEnrollment{
		ID:              "enroll-1",
		DeviceID:        "device-1",
		OrganizationID:  transportTestOrganizationID,
		Component:       "endpoint",
		Status:          "approved",
		CertPEM:         string(deviceCertPEM),
		CertFingerprint: clientCertificateFingerprint(deviceCert),
		EnrolledAt:      time.Now().Add(-time.Minute),
		ExpiresAt:       time.Now().Add(time.Hour),
	}
	dataStore.SaveDeviceEnrollment(enrollment)

	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: *deviceTLSState(deviceCert)}})
	ctx = context.WithValue(ctx, deviceEnrollmentContextKey, enrollment)
	request, err := structpb.NewStruct(map[string]interface{}{
		"device_id": "device-1",
	})
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	_, err = (&agentSessionGRPCService{server: server}).StartSession(ctx, request)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("StartSession() error = %v, want FailedPrecondition", err)
	}
}

func TestAgentSessionRevokeSessionRevokesResourceSessions(t *testing.T) {
	server, dataStore := newDeviceAPITestServer(t)

	deviceCertPEM, deviceCert := newDeviceAPICertificate(t, "device-1", time.Now().Add(time.Hour))
	enrollment := &models.DeviceEnrollment{
		ID:              "enroll-1",
		DeviceID:        "device-1",
		OrganizationID:  transportTestOrganizationID,
		Component:       "endpoint",
		Status:          "approved",
		CertPEM:         string(deviceCertPEM),
		CertFingerprint: clientCertificateFingerprint(deviceCert),
		EnrolledAt:      time.Now().Add(-time.Minute),
		ExpiresAt:       time.Now().Add(time.Hour),
	}
	dataStore.SaveDeviceEnrollment(enrollment)
	token := newDeviceCatalogAccessToken(t, server, dataStore, "device-1", "admin", clientCertificateFingerprint(deviceCert))
	server.agentSessions.save(&agentSessionTransaction{
		ID:                    "srq-1",
		OrganizationID:        transportTestOrganizationID,
		DeviceID:              "device-1",
		DeviceCertThumbprint:  clientCertificateFingerprint(deviceCert),
		LocalUserSIDHash:      "sid-hash",
		WindowsLogonSessionID: "logon-session",
		WindowsSessionID:      "1",
		AgentSessionID:        "sess-test",
		Status:                agentSessionStatusClaimed,
		CreatedAt:             time.Now().Add(-time.Minute),
		LastActivityAt:        time.Now().Add(-time.Minute),
		IdleExpiresAt:         time.Now().Add(time.Hour),
		AbsoluteExpiresAt:     time.Now().Add(8 * time.Hour),
		ExpiresAt:             time.Now().Add(time.Hour),
	})

	now := time.Now()
	dataStore.SaveSession(&models.Session{
		ID:             "resource-session-1",
		UserID:         "user-1",
		Username:       "alice@example.test",
		DeviceID:       "device-1",
		Resource:       "res-ssh",
		GatewayID:      "gw-1",
		Protocol:       "ssh",
		OrganizationID: transportTestOrganizationID,
		CreatedAt:      now.Add(-time.Minute),
		ExpiresAt:      now.Add(time.Hour),
	})
	dataStore.SaveSession(&models.Session{
		ID:             "other-device-session",
		UserID:         "user-1",
		Username:       "alice@example.test",
		DeviceID:       "device-2",
		Resource:       "res-rdp",
		GatewayID:      "gw-1",
		Protocol:       "rdp",
		OrganizationID: transportTestOrganizationID,
		CreatedAt:      now.Add(-time.Minute),
		ExpiresAt:      now.Add(time.Hour),
	})

	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: *deviceTLSState(deviceCert)}})
	ctx = context.WithValue(ctx, deviceEnrollmentContextKey, enrollment)
	request, err := structpb.NewStruct(map[string]interface{}{
		"access_token": token,
		"session_id":   "sess-test",
	})
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	response, err := (&agentSessionGRPCService{server: server}).RevokeSession(ctx, request)
	if err != nil {
		t.Fatalf("RevokeSession() error = %v", err)
	}
	gotRevoked, _ := response.AsMap()["revoked_resource_sessions"].(float64)
	if got := int(gotRevoked); got != 1 {
		t.Fatalf("revoked_resource_sessions = %d, want 1", got)
	}
	if !dataStore.IsTokenRevoked(jwtIDFromToken(t, server, token)) {
		t.Fatalf("agent session token was not revoked")
	}
	if _, ok := server.agentSessions.get("srq-1"); ok {
		t.Fatalf("agent session transaction was not deleted")
	}
	resourceSession, ok := dataStore.GetSession("resource-session-1")
	if !ok || !resourceSession.Revoked {
		t.Fatalf("resource session revoked = %v found=%v", ok && resourceSession.Revoked, ok)
	}
	foundDisconnectAudit := false
	for _, entry := range dataStore.GetAuditLog(10) {
		if entry.EventType == "agent_resource_session_ended" &&
			entry.UserID == "user-1" &&
			entry.Resource == "res-ssh" &&
			entry.Decision == "ended" &&
			entry.Success {
			foundDisconnectAudit = true
			break
		}
	}
	if !foundDisconnectAudit {
		t.Fatalf("audit log missing agent_resource_session_ended event: %+v", dataStore.GetAuditLog(10))
	}
	otherSession, ok := dataStore.GetSession("other-device-session")
	if !ok || otherSession.Revoked {
		t.Fatalf("other device session should remain active, session=%#v found=%v", otherSession, ok)
	}
}

func TestResourceSessionAuditEventForSourceIPChange(t *testing.T) {
	eventType, decision, details := resourceSessionAuditEvent("source_ip_changed")
	if eventType != "agent_resource_session_revoked" || decision != "revoked" {
		t.Fatalf("audit event = %q/%q, want revoked resource session", eventType, decision)
	}
	if details != "Resource session revoked because source IP changed" {
		t.Fatalf("details = %q, want source IP change message", details)
	}
}

func TestAgentSessionRenewDoesNotExtendIdleTimeout(t *testing.T) {
	server, dataStore := newDeviceAPITestServer(t)

	deviceCertPEM, deviceCert := newDeviceAPICertificate(t, "device-1", time.Now().Add(time.Hour))
	enrollment := &models.DeviceEnrollment{
		ID:              "enroll-1",
		DeviceID:        "device-1",
		OrganizationID:  transportTestOrganizationID,
		Component:       "endpoint",
		Status:          "approved",
		CertPEM:         string(deviceCertPEM),
		CertFingerprint: clientCertificateFingerprint(deviceCert),
		EnrolledAt:      time.Now().Add(-time.Minute),
		ExpiresAt:       time.Now().Add(time.Hour),
	}
	dataStore.SaveDeviceEnrollment(enrollment)
	token := newDeviceCatalogAccessToken(t, server, dataStore, "device-1", "admin", clientCertificateFingerprint(deviceCert))

	lastActivityAt := time.Now().UTC().Add(-10 * time.Minute)
	idleExpiresAt := time.Now().UTC().Add(20 * time.Minute)
	absoluteExpiresAt := time.Now().UTC().Add(8 * time.Hour)
	server.agentSessions.save(&agentSessionTransaction{
		ID:                    "srq-1",
		OrganizationID:        transportTestOrganizationID,
		DeviceID:              "device-1",
		DeviceCertThumbprint:  clientCertificateFingerprint(deviceCert),
		LocalUserSIDHash:      "sid-hash",
		WindowsLogonSessionID: "logon-session",
		WindowsSessionID:      "1",
		AgentSessionID:        "sess-test",
		Status:                agentSessionStatusClaimed,
		CreatedAt:             time.Now().UTC().Add(-15 * time.Minute),
		LastActivityAt:        lastActivityAt,
		IdleExpiresAt:         idleExpiresAt,
		AbsoluteExpiresAt:     absoluteExpiresAt,
		ExpiresAt:             idleExpiresAt,
	})

	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: *deviceTLSState(deviceCert)}})
	ctx = context.WithValue(ctx, deviceEnrollmentContextKey, enrollment)
	request, err := structpb.NewStruct(map[string]interface{}{
		"access_token": token,
		"session_id":   "sess-test",
	})
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	response, err := (&agentSessionGRPCService{server: server}).RenewSession(ctx, request)
	if err != nil {
		t.Fatalf("RenewSession() error = %v", err)
	}
	if strings.TrimSpace(structFieldString(response, "agent_session_token")) == "" {
		t.Fatalf("renew response does not include a new agent session token")
	}
	if !dataStore.IsTokenRevoked(jwtIDFromToken(t, server, token)) {
		t.Fatalf("old agent session token was not revoked")
	}
	updated, ok := server.agentSessions.get("srq-1")
	if !ok {
		t.Fatalf("agent session transaction not found after renew")
	}
	if !updated.LastActivityAt.Equal(lastActivityAt) {
		t.Fatalf("LastActivityAt changed on renew: got %s want %s", updated.LastActivityAt, lastActivityAt)
	}
	if !updated.IdleExpiresAt.Equal(idleExpiresAt) {
		t.Fatalf("IdleExpiresAt changed on renew: got %s want %s", updated.IdleExpiresAt, idleExpiresAt)
	}
	if !updated.AbsoluteExpiresAt.Equal(absoluteExpiresAt) {
		t.Fatalf("AbsoluteExpiresAt changed on renew: got %s want %s", updated.AbsoluteExpiresAt, absoluteExpiresAt)
	}
	if !updated.ExpiresAt.Equal(idleExpiresAt) {
		t.Fatalf("ExpiresAt changed on renew: got %s want %s", updated.ExpiresAt, idleExpiresAt)
	}
}

func jwtIDFromToken(t *testing.T, server *Server, token string) string {
	t.Helper()
	claims, err := server.pa.Auth.JWT.ParseAuthToken(token)
	if err != nil {
		t.Fatalf("ParseAuthToken() error = %v", err)
	}
	return claims.ID
}
