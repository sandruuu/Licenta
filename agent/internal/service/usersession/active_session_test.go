package usersession

import (
	"context"
	"strings"
	"sync"
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

func TestAuthenticatedSessionExpiryRevokesAndClears(t *testing.T) {
	client := &recordingSessionClient{}
	cleared := make(chan ipc.PeerIdentity, 1)
	manager := NewManager(Config{}, Dependencies{
		Client: client,
		Clock:  time.Now,
		OnLogout: func(_ context.Context, peer ipc.PeerIdentity) error {
			cleared <- peer
			return nil
		},
	})
	peer := ipc.PeerIdentity{
		UserSID:               "S-1-5-21-1000",
		WindowsLogonSessionID: "00000000:000003e7",
		WindowsSessionID:      "1",
		Verified:              true,
	}
	key, err := localUserKey(peer)
	if err != nil {
		t.Fatalf("localUserKey returned error: %v", err)
	}
	manager.sessions[key] = &sessionState{
		key:               key,
		peer:              peer,
		state:             ipc.UserSessionStateAuthenticated,
		agentSessionID:    "sess-expiring",
		agentSessionToken: "agent-token",
		expiresAt:         time.Now().Add(50 * time.Millisecond),
		catalog: ipc.CatalogInfo{Resources: []ipc.CatalogResource{{
			ResourceID: "res-web",
			FQDN:       "web.internal.example",
		}}},
	}

	manager.startAuthenticatedSessionExpiryWatcher(key)

	select {
	case gotPeer := <-cleared:
		if gotPeer.UserSID != peer.UserSID {
			t.Fatalf("cleared peer = %+v", gotPeer)
		}
	case <-time.After(time.Second):
		t.Fatal("session expiry cleanup did not run")
	}
	if _, found, err := manager.ActiveAuthenticatedSession(); err != nil || found {
		t.Fatalf("active session found=%v err=%v, want signed out", found, err)
	}
	if snapshot := manager.Snapshot(peer); snapshot.UserSession.State != ipc.UserSessionStateSignedOut || !strings.Contains(snapshot.UserSession.Message, "expired") || len(snapshot.Catalog.Resources) != 0 {
		t.Fatalf("snapshot after expiry = %+v catalog=%+v", snapshot.UserSession, snapshot.Catalog)
	}
	revokes := client.revokeRequests()
	if len(revokes) != 1 || revokes[0].AgentSessionToken != "agent-token" || revokes[0].SessionID != "sess-expiring" {
		t.Fatalf("revoke requests = %+v", revokes)
	}
}

func TestRemoteRevokeSignsOutAndClearsAccess(t *testing.T) {
	cleared := make(chan ipc.PeerIdentity, 1)
	manager := NewManager(Config{}, Dependencies{
		Clock: time.Now,
		OnLogout: func(_ context.Context, peer ipc.PeerIdentity) error {
			cleared <- peer
			return nil
		},
	})
	peer := ipc.PeerIdentity{
		UserSID:               "S-1-5-21-2000",
		WindowsLogonSessionID: "00000000:00000400",
		WindowsSessionID:      "1",
		Verified:              true,
	}
	key, err := localUserKey(peer)
	if err != nil {
		t.Fatalf("localUserKey returned error: %v", err)
	}
	manager.sessions[key] = &sessionState{
		key:               key,
		peer:              peer,
		state:             ipc.UserSessionStateAuthenticated,
		agentSessionID:    "sess-revoked",
		agentSessionToken: "agent-token",
		expiresAt:         time.Now().Add(time.Hour),
	}

	if !manager.RevokeRemote(context.Background(), "sess-revoked", "Firewall is disabled.") {
		t.Fatal("RevokeRemote() = false, want true")
	}
	select {
	case gotPeer := <-cleared:
		if gotPeer.UserSID != peer.UserSID {
			t.Fatalf("cleared peer = %+v", gotPeer)
		}
	case <-time.After(time.Second):
		t.Fatal("remote revoke did not clear protected resources")
	}
	snapshot := manager.Snapshot(peer)
	if snapshot.UserSession.State != ipc.UserSessionStateSignedOut || snapshot.UserSession.Message != "Firewall is disabled." {
		t.Fatalf("snapshot after remote revoke = %+v", snapshot.UserSession)
	}
}

func TestRefreshCatalogAppliesUpdatedCatalog(t *testing.T) {
	client := &recordingSessionClient{
		catalog: CatalogResponse{
			Version:    "catalog-v2",
			TTLSeconds: 300,
			Resources: []ipc.CatalogResource{{
				ResourceID: "res-new",
				FQDN:       "new.internal.example",
				Protocol:   "https",
				Port:       443,
			}},
			PolicyEpoch: "2",
		},
	}
	applied := make(chan ipc.CatalogInfo, 1)
	manager := NewManager(Config{}, Dependencies{
		Client: client,
		Clock:  time.Now,
		OnCatalog: func(_ context.Context, _ ipc.PeerIdentity, catalog ipc.CatalogInfo) error {
			applied <- catalog
			return nil
		},
	})
	peer := ipc.PeerIdentity{
		UserSID:               "S-1-5-21-3000",
		WindowsLogonSessionID: "00000000:00000401",
		WindowsSessionID:      "1",
		Verified:              true,
	}
	key, err := localUserKey(peer)
	if err != nil {
		t.Fatalf("localUserKey returned error: %v", err)
	}
	manager.sessions[key] = &sessionState{
		key:               key,
		peer:              peer,
		state:             ipc.UserSessionStateAuthenticated,
		agentSessionID:    "sess-catalog",
		agentSessionToken: "agent-token",
		expiresAt:         time.Now().Add(time.Hour),
	}

	if err := manager.RefreshCatalog(context.Background(), "sess-catalog"); err != nil {
		t.Fatalf("RefreshCatalog() error = %v", err)
	}
	select {
	case catalog := <-applied:
		if catalog.Version != "catalog-v2" || len(catalog.Resources) != 1 || catalog.Resources[0].ResourceID != "res-new" {
			t.Fatalf("applied catalog = %+v", catalog)
		}
	case <-time.After(time.Second):
		t.Fatal("catalog refresh did not apply catalog")
	}
	snapshot := manager.Snapshot(peer)
	if snapshot.Catalog.Version != "catalog-v2" || len(snapshot.Catalog.Resources) != 1 {
		t.Fatalf("snapshot catalog = %+v", snapshot.Catalog)
	}
}

type recordingSessionClient struct {
	mu      sync.Mutex
	revokes []RevokeSessionRequest
	catalog CatalogResponse
}

func (client *recordingSessionClient) StartSession(context.Context, StartSessionRequest) (StartSessionResponse, error) {
	return StartSessionResponse{}, nil
}

func (client *recordingSessionClient) SessionStatus(context.Context, SessionStatusRequest) (SessionStatusResponse, error) {
	return SessionStatusResponse{}, nil
}

func (client *recordingSessionClient) ClaimSession(context.Context, ClaimSessionRequest) (ClaimSessionResponse, error) {
	return ClaimSessionResponse{}, nil
}

func (client *recordingSessionClient) GetCatalog(context.Context, GetCatalogRequest) (CatalogResponse, error) {
	return client.catalog, nil
}

func (client *recordingSessionClient) RevokeSession(_ context.Context, request RevokeSessionRequest) error {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.revokes = append(client.revokes, request)
	return nil
}

func (client *recordingSessionClient) Close() error {
	return nil
}

func (client *recordingSessionClient) revokeRequests() []RevokeSessionRequest {
	client.mu.Lock()
	defer client.mu.Unlock()
	return append([]RevokeSessionRequest(nil), client.revokes...)
}
