package transport

import (
	"context"
	"testing"
	"time"

	"pdp/models"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/structpb"
)

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
		ID:                "srq-1",
		OrganizationID:    transportTestOrganizationID,
		DeviceID:          "device-1",
		AgentSessionID:    "sess-test",
		AgentSessionToken: token,
		Status:            agentSessionStatusClaimed,
		CreatedAt:         time.Now().Add(-time.Minute),
		ExpiresAt:         time.Now().Add(time.Hour),
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
	otherSession, ok := dataStore.GetSession("other-device-session")
	if !ok || otherSession.Revoked {
		t.Fatalf("other device session should remain active, session=%#v found=%v", otherSession, ok)
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
