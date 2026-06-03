package dataplane

import (
	"encoding/json"
	"net"
	"testing"
	"time"

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

	session, code, message := gateway.validateProvisionedConnect(&ConnectRequest{
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
	_, code, message := gateway.validateProvisionedConnect(&ConnectRequest{
		Token:      "legacy-access-token",
		DeviceID:   "device-1",
		RemoteAddr: "100.64.0.10",
		RemotePort: 22,
	}, &connectionState{certDeviceID: "device-1"})
	if code != CodeSessionInvalid {
		t.Fatalf("code = %q, want %q (message=%q)", code, CodeSessionInvalid, message)
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

	_, code, message := gateway.validateProvisionedConnect(&ConnectRequest{
		SessionID:    "sess-1",
		SessionToken: "session-secret",
		DeviceID:     "device-1",
		ResourceID:   "res-ssh",
		Protocol:     "ssh",
		RemotePort:   22,
	}, &connectionState{certDeviceID: "device-1"})
	if code != CodeSessionInvalid {
		t.Fatalf("code = %q, want %q (message=%q)", code, CodeSessionInvalid, message)
	}
}

func TestRevokeProvisionedSessionTerminatesActiveRelays(t *testing.T) {
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

	revoked := make(chan string, 1)
	gateway.activeRelays.Store("relay-1", &activeRelay{
		id:        "relay-1",
		sessionID: "sess-1",
		cancel: func(reason string) {
			revoked <- reason
		},
	})
	untouched := make(chan string, 1)
	gateway.activeRelays.Store("relay-2", &activeRelay{
		id:        "relay-2",
		sessionID: "other-session",
		cancel: func(reason string) {
			untouched <- reason
		},
	})

	if !gateway.RevokeProvisionedSession("sess-1", "agent_logout") {
		t.Fatal("RevokeProvisionedSession() = false")
	}
	select {
	case reason := <-revoked:
		if reason != "session.revoked" {
			t.Fatalf("relay close reason = %q, want session.revoked", reason)
		}
	case <-time.After(time.Second):
		t.Fatal("active relay for revoked session was not terminated")
	}
	select {
	case reason := <-untouched:
		t.Fatalf("unrelated relay was terminated with reason %q", reason)
	default:
	}
}

func TestProvisionSessionRenewsActiveRelays(t *testing.T) {
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	gateway := &Gateway{provisioned: provisioning.NewStoreWithClock(func() time.Time { return now })}
	renewed := make(chan time.Time, 1)
	gateway.activeRelays.Store("relay-1", &activeRelay{
		id:        "relay-1",
		sessionID: "sess-1",
		renew:     renewed,
		cancel:    func(string) {},
	})
	nextExpiry := now.Add(30 * time.Minute)
	if err := gateway.ProvisionSession(provisioning.Session{
		ID:           "sess-1",
		DeviceID:     "device-1",
		UserID:       "user-1",
		ResourceID:   "res-ssh",
		InternalHost: "10.10.0.10",
		InternalPort: 22,
		Protocol:     "ssh",
		ExpiresAt:    nextExpiry,
	}, "rotated-session-secret"); err != nil {
		t.Fatalf("ProvisionSession() error = %v", err)
	}
	select {
	case got := <-renewed:
		if !got.Equal(nextExpiry) {
			t.Fatalf("renewed expiry = %s, want %s", got, nextExpiry)
		}
	case <-time.After(time.Second):
		t.Fatal("active relay did not receive renewed expiry")
	}
}

func TestCleanupExpiredProvisionedSessionsRemovesSessionsAndTerminatesRelays(t *testing.T) {
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	gateway := &Gateway{provisioned: provisioning.NewStoreWithClock(func() time.Time { return now })}
	if err := gateway.ProvisionSession(provisioning.Session{
		ID:           "sess-expiring",
		DeviceID:     "device-1",
		UserID:       "user-1",
		ResourceID:   "res-ssh",
		InternalHost: "10.10.0.10",
		InternalPort: 22,
		Protocol:     "ssh",
		ExpiresAt:    now.Add(time.Minute),
	}, "session-secret"); err != nil {
		t.Fatalf("ProvisionSession() error = %v", err)
	}
	closed := make(chan string, 1)
	gateway.activeRelays.Store("relay-expiring", &activeRelay{
		id:        "relay-expiring",
		sessionID: "sess-expiring",
		cancel: func(reason string) {
			closed <- reason
		},
	})

	now = now.Add(2 * time.Minute)
	gateway.cleanupExpiredProvisionedSessions()

	if count := gateway.ProvisionedSessionCount(); count != 0 {
		t.Fatalf("ProvisionedSessionCount() = %d, want 0", count)
	}
	select {
	case reason := <-closed:
		if reason != "session.expired" {
			t.Fatalf("relay close reason = %q, want session.expired", reason)
		}
	case <-time.After(time.Second):
		t.Fatal("expired relay was not terminated")
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
	var response ConnectResponse
	if err := json.NewDecoder(clientConn).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Code != CodeBadRequest {
		t.Fatalf("code = %q, want %q", response.Code, CodeBadRequest)
	}
	<-done
}
