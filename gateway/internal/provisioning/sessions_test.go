package provisioning

import (
	"testing"
	"time"
)

func TestStoreValidatesProvisionedSession(t *testing.T) {
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	store := NewStoreWithClock(func() time.Time { return now })

	err := store.Provision(Session{
		ID:           "sess-1",
		DeviceID:     "device-1",
		UserID:       "user-1",
		Username:     "alice",
		ResourceID:   "res-ssh",
		ResourceName: "SSH Server",
		InternalHost: "10.10.0.10",
		InternalPort: 22,
		Protocol:     "SSH",
		ExpiresAt:    now.Add(time.Hour),
	}, "session-secret")
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}

	session, err := store.Validate(ConnectCheck{
		SessionID:    "sess-1",
		SessionToken: "session-secret",
		DeviceID:     "device-1",
		ResourceID:   "res-ssh",
		Protocol:     "ssh",
		Port:         22,
	})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if session.InternalHost != "10.10.0.10" || session.InternalPort != 22 || session.Protocol != "ssh" {
		t.Fatalf("Validate() returned wrong session: %+v", session)
	}
	if session.TokenHash == "session-secret" {
		t.Fatal("raw session token must not be stored")
	}
}

func TestStoreRejectsInvalidBindings(t *testing.T) {
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	store := NewStoreWithClock(func() time.Time { return now })
	if err := store.Provision(Session{
		ID:           "sess-1",
		DeviceID:     "device-1",
		UserID:       "user-1",
		ResourceID:   "res-ssh",
		InternalHost: "10.10.0.10",
		InternalPort: 22,
		Protocol:     "ssh",
		ExpiresAt:    now.Add(time.Hour),
	}, "session-secret"); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}

	tests := []struct {
		name string
		in   ConnectCheck
		code string
	}{
		{name: "bad token", in: ConnectCheck{SessionID: "sess-1", SessionToken: "wrong", DeviceID: "device-1", ResourceID: "res-ssh", Protocol: "ssh", Port: 22}, code: CodeInvalidToken},
		{name: "wrong device", in: ConnectCheck{SessionID: "sess-1", SessionToken: "session-secret", DeviceID: "device-2", ResourceID: "res-ssh", Protocol: "ssh", Port: 22}, code: CodeDeviceMismatch},
		{name: "wrong resource", in: ConnectCheck{SessionID: "sess-1", SessionToken: "session-secret", DeviceID: "device-1", ResourceID: "res-rdp", Protocol: "ssh", Port: 22}, code: CodeResourceMismatch},
		{name: "wrong port", in: ConnectCheck{SessionID: "sess-1", SessionToken: "session-secret", DeviceID: "device-1", ResourceID: "res-ssh", Protocol: "ssh", Port: 3389}, code: CodeResourceMismatch},
		{name: "wrong protocol", in: ConnectCheck{SessionID: "sess-1", SessionToken: "session-secret", DeviceID: "device-1", ResourceID: "res-ssh", Protocol: "rdp", Port: 22}, code: CodeProtocolMismatch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := store.Validate(tt.in)
			validationErr, ok := AsValidationError(err)
			if !ok || validationErr.Code != tt.code {
				t.Fatalf("Validate() error = %#v, want code %q", err, tt.code)
			}
		})
	}
}

func TestStoreRejectsExpiredAndRevokedSessions(t *testing.T) {
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	store := NewStoreWithClock(func() time.Time { return now })
	if err := store.Provision(Session{
		ID:           "sess-1",
		DeviceID:     "device-1",
		UserID:       "user-1",
		ResourceID:   "res-ssh",
		InternalHost: "10.10.0.10",
		InternalPort: 22,
		Protocol:     "ssh",
		ExpiresAt:    now.Add(time.Hour),
	}, "session-secret"); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}

	if _, ok := store.Revoke("sess-1", "admin_revoked"); !ok {
		t.Fatal("Revoke() did not find session")
	}
	_, err := store.Validate(ConnectCheck{SessionID: "sess-1", SessionToken: "session-secret", DeviceID: "device-1", ResourceID: "res-ssh", Protocol: "ssh", Port: 22})
	validationErr, ok := AsValidationError(err)
	if !ok || validationErr.Code != CodeSessionRevoked {
		t.Fatalf("Validate() revoked error = %#v", err)
	}

	store = NewStoreWithClock(func() time.Time { return now })
	if err := store.Provision(Session{ID: "expired", DeviceID: "device-1", ResourceID: "res-ssh", InternalHost: "10.10.0.10", InternalPort: 22, Protocol: "ssh", ExpiresAt: now.Add(-time.Second)}, "token"); err == nil {
		t.Fatal("Provision() accepted expired session")
	}
}

func TestStoreListSessionsReturnsCopies(t *testing.T) {
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	store := NewStoreWithClock(func() time.Time { return now })
	if err := store.Provision(Session{
		ID:           "sess-1",
		DeviceID:     "device-1",
		UserID:       "user-1",
		ResourceID:   "res-ssh",
		InternalHost: "10.10.0.10",
		InternalPort: 22,
		Protocol:     "ssh",
		ExpiresAt:    now.Add(time.Hour),
		Constraints:  []string{"policy:one"},
	}, "session-secret"); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}

	sessions := store.ListSessions()
	if len(sessions) != 1 || sessions[0].ID != "sess-1" {
		t.Fatalf("ListSessions() = %+v", sessions)
	}
	sessions[0].Constraints[0] = "mutated"
	again := store.ListSessions()
	if again[0].Constraints[0] != "policy:one" {
		t.Fatalf("ListSessions() leaked mutable constraints: %+v", again[0].Constraints)
	}
}

func TestStorePurgeExpiredRemovesExpiredSessions(t *testing.T) {
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	store := NewStoreWithClock(func() time.Time { return now })
	if err := store.Provision(Session{
		ID:           "expired-soon",
		DeviceID:     "device-1",
		UserID:       "user-1",
		ResourceID:   "res-ssh",
		InternalHost: "10.10.0.10",
		InternalPort: 22,
		Protocol:     "ssh",
		ExpiresAt:    now.Add(time.Minute),
		Constraints:  []string{"policy:one"},
	}, "session-secret"); err != nil {
		t.Fatalf("Provision() expired-soon error = %v", err)
	}
	if err := store.Provision(Session{
		ID:           "still-valid",
		DeviceID:     "device-1",
		UserID:       "user-1",
		ResourceID:   "res-rdp",
		InternalHost: "10.10.0.11",
		InternalPort: 3389,
		Protocol:     "rdp",
		ExpiresAt:    now.Add(time.Hour),
	}, "other-secret"); err != nil {
		t.Fatalf("Provision() still-valid error = %v", err)
	}

	now = now.Add(2 * time.Minute)
	expired := store.PurgeExpired()
	if len(expired) != 1 || expired[0].ID != "expired-soon" {
		t.Fatalf("PurgeExpired() = %+v, want expired-soon", expired)
	}
	if store.Count() != 1 {
		t.Fatalf("Count() = %d, want 1", store.Count())
	}
	if _, err := store.Validate(ConnectCheck{SessionID: "expired-soon", SessionToken: "session-secret", DeviceID: "device-1", ResourceID: "res-ssh", Protocol: "ssh", Port: 22}); err == nil {
		t.Fatal("Validate() accepted purged session")
	}
	if _, err := store.Validate(ConnectCheck{SessionID: "still-valid", SessionToken: "other-secret", DeviceID: "device-1", ResourceID: "res-rdp", Protocol: "rdp", Port: 3389}); err != nil {
		t.Fatalf("Validate() valid session error = %v", err)
	}
}
