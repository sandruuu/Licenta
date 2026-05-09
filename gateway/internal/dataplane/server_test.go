package dataplane

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"gateway/internal/auth"
	"gateway/internal/provisioning"
)

func TestValidateProvisionedConnectAcceptsPASession(t *testing.T) {
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	gateway := &Gateway{provisioned: provisioning.NewStoreWithClock(func() time.Time { return now })}
	if err := gateway.ProvisionSession(provisioning.Session{
		ID:           "sess-1",
		DeviceID:     "device-1",
		UserID:       "user-1",
		Username:     "alice",
		ResourceID:   "res-ssh",
		ResourceName: "SSH Server",
		InternalHost: "10.10.0.10",
		InternalPort: 22,
		Protocol:     "ssh",
		ExpiresAt:    now.Add(time.Hour),
	}, "session-secret"); err != nil {
		t.Fatalf("ProvisionSession() error = %v", err)
	}

	session, code, message := gateway.validateProvisionedConnect(&auth.ConnectRequest{
		SessionID:    "sess-1",
		SessionToken: "session-secret",
		DeviceID:     "device-1",
		ResourceID:   "res-ssh",
		Protocol:     "ssh",
		RemotePort:   22,
	}, &connectionState{certDeviceID: "device-1"})
	if code != "" || message != "" {
		t.Fatalf("validateProvisionedConnect() code=%q message=%q", code, message)
	}
	if session == nil || session.ID != "sess-1" || session.InternalHost != "10.10.0.10" {
		t.Fatalf("validateProvisionedConnect() session = %+v", session)
	}
}

func TestValidateProvisionedConnectRejectsLegacyBearerOnly(t *testing.T) {
	gateway := &Gateway{provisioned: provisioning.NewStore()}
	_, code, message := gateway.validateProvisionedConnect(&auth.ConnectRequest{
		Token:      "cloud-access-token",
		DeviceID:   "device-1",
		RemoteAddr: "100.64.0.10",
		RemotePort: 22,
	}, &connectionState{certDeviceID: "device-1"})
	if code != auth.CodeSessionInvalid {
		t.Fatalf("code = %q, want %q (message=%q)", code, auth.CodeSessionInvalid, message)
	}
}

func TestRevokeProvisionedSessionDeniesConnect(t *testing.T) {
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	gateway := &Gateway{provisioned: provisioning.NewStoreWithClock(func() time.Time { return now })}
	if err := gateway.ProvisionSession(provisioning.Session{
		ID:           "sess-1",
		DeviceID:     "device-1",
		UserID:       "user-1",
		ResourceID:   "res-ssh",
		InternalHost: "10.10.0.10",
		InternalPort: 22,
		Protocol:     "ssh",
		ExpiresAt:    now.Add(time.Hour),
	}, "session-secret"); err != nil {
		t.Fatalf("ProvisionSession() error = %v", err)
	}
	if !gateway.RevokeProvisionedSession("sess-1", "admin_revoked") {
		t.Fatal("RevokeProvisionedSession() = false")
	}

	_, code, message := gateway.validateProvisionedConnect(&auth.ConnectRequest{
		SessionID:    "sess-1",
		SessionToken: "session-secret",
		DeviceID:     "device-1",
		ResourceID:   "res-ssh",
		Protocol:     "ssh",
		RemotePort:   22,
	}, &connectionState{certDeviceID: "device-1"})
	if code != auth.CodeSessionInvalid {
		t.Fatalf("code = %q, want %q (message=%q)", code, auth.CodeSessionInvalid, message)
	}
}

func TestDNSResolveIsNotAcceptedByStrictGateway(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		gateway := &Gateway{}
		gateway.handleStream(serverConn, &connectionState{remoteAddr: "pipe"})
		close(done)
	}()

	if _, err := clientConn.Write([]byte(`{"type":"dns_resolve","domain":"db.internal"}` + "\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	var response auth.ConnectResponse
	if err := json.NewDecoder(clientConn).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Code != auth.CodeBadRequest {
		t.Fatalf("code = %q, want %q", response.Code, auth.CodeBadRequest)
	}
	<-done
}
