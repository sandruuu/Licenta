package usersession

import (
	"strings"
	"testing"
	"time"

	"agent/internal/shared/ipc"
)

func TestActiveAuthenticatedSessionReturnsOnlyAuthenticatedSession(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	manager := NewManager(Config{}, Dependencies{Clock: func() time.Time { return now }})
	manager.sessions["auth"] = &sessionState{
		state:             ipc.UserSessionStateAuthenticated,
		agentSessionID:    "sess-1",
		agentSessionToken: "agent-token",
		displayName:       "User",
		email:             "user@example.test",
		expiresAt:         now.Add(time.Hour),
	}
	manager.sessions["pending"] = &sessionState{state: ipc.UserSessionStateAuthenticating}

	session, found, err := manager.ActiveAuthenticatedSession()
	if err != nil {
		t.Fatalf("ActiveAuthenticatedSession returned error: %v", err)
	}
	if !found || session.AgentSessionToken != "agent-token" || session.AgentSessionID != "sess-1" {
		t.Fatalf("session=%+v found=%v", session, found)
	}
}

func TestActiveAuthenticatedSessionRejectsMultipleAuthenticatedSessions(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	manager := NewManager(Config{}, Dependencies{Clock: func() time.Time { return now }})
	manager.sessions["one"] = &sessionState{state: ipc.UserSessionStateAuthenticated, agentSessionToken: "one", expiresAt: now.Add(time.Hour)}
	manager.sessions["two"] = &sessionState{state: ipc.UserSessionStateAuthenticated, agentSessionToken: "two", expiresAt: now.Add(time.Hour)}

	_, _, err := manager.ActiveAuthenticatedSession()
	if err == nil || !strings.Contains(err.Error(), "multiple authenticated") {
		t.Fatalf("error = %v", err)
	}
}

func TestActiveAuthenticatedSessionIgnoresExpiredSession(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	manager := NewManager(Config{}, Dependencies{Clock: func() time.Time { return now }})
	manager.sessions["expired"] = &sessionState{state: ipc.UserSessionStateAuthenticated, agentSessionToken: "expired", expiresAt: now.Add(-time.Minute)}

	_, found, err := manager.ActiveAuthenticatedSession()
	if err != nil {
		t.Fatalf("ActiveAuthenticatedSession returned error: %v", err)
	}
	if found {
		t.Fatalf("found expired session")
	}
}
