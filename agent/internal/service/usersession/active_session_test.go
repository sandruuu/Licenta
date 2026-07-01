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

func TestDashboardSnapshotFallsBackToSameUserSessionWhenPeerKeyIsIncomplete(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	manager := NewManager(Config{}, Dependencies{Clock: func() time.Time { return now }})
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
		agentSessionID:    "sess-1",
		agentSessionToken: "agent-token",
		expiresAt:         now.Add(time.Hour),
		catalog: ipc.CatalogInfo{Resources: []ipc.CatalogResource{{
			ResourceID: "res-rdp",
			FQDN:       "rdp-desktop.trustcloud.test",
		}}},
	}

	snapshot := manager.DashboardSnapshot(ipc.PeerIdentity{
		UserSID:          peer.UserSID,
		WindowsSessionID: peer.WindowsSessionID,
		Verified:         true,
	})

	if snapshot.UserSession.State != ipc.UserSessionStateAuthenticated || snapshot.UserSession.SessionID != "sess-1" {
		t.Fatalf("dashboard snapshot = %+v", snapshot.UserSession)
	}
	if len(snapshot.Catalog.Resources) != 1 || snapshot.Catalog.Resources[0].ResourceID != "res-rdp" {
		t.Fatalf("dashboard catalog = %+v", snapshot.Catalog)
	}
}

func TestDashboardSnapshotDoesNotFallbackWhenSameUserSessionsAreAmbiguous(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	manager := NewManager(Config{}, Dependencies{Clock: func() time.Time { return now }})
	for _, windowsSessionID := range []string{"1", "2"} {
		peer := ipc.PeerIdentity{
			UserSID:               "S-1-5-21-1000",
			WindowsLogonSessionID: "00000000:000003e7",
			WindowsSessionID:      windowsSessionID,
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
			agentSessionID:    "sess-" + windowsSessionID,
			agentSessionToken: "agent-token",
			expiresAt:         now.Add(time.Hour),
		}
	}

	snapshot := manager.DashboardSnapshot(ipc.PeerIdentity{
		UserSID:  "S-1-5-21-1000",
		Verified: true,
	})

	if snapshot.UserSession.State != ipc.UserSessionStateSignedOut || len(snapshot.Catalog.Resources) != 0 {
		t.Fatalf("dashboard snapshot should be signed out when fallback is ambiguous: %+v catalog=%+v", snapshot.UserSession, snapshot.Catalog)
	}
}

func TestAuthenticatedStepUpMessagesIncludeResourceTarget(t *testing.T) {
	manager := NewManager(Config{TrustedStepUpHosts: []string{"pdp.example.test"}}, Dependencies{})
	manager.sessions["auth"] = &sessionState{
		key:               "auth",
		state:             ipc.UserSessionStateAuthenticated,
		agentSessionToken: "agent-token",
		expiresAt:         time.Now().Add(time.Hour),
	}

	manager.SetAuthenticatedStepUp(
		"Additional security verification is required to access rdp-desktop.trustcloud.test.",
		"https://pdp.example.test/verify/stepup-1",
		"res-rdp",
		"rdp-desktop.trustcloud.test",
		time.Now().Add(time.Minute),
	)

	session := manager.sessions["auth"]
	if session.stepUpURL == "" || session.message != "Additional security verification is required to access rdp-desktop.trustcloud.test." {
		t.Fatalf("step-up session = %+v", session)
	}

	manager.MarkAuthenticatedStepUpAllowed("res-rdp", "rdp-desktop.trustcloud.test")
	if session.stepUpURL != "" || session.lastError != "" || session.message != "Access granted to rdp-desktop.trustcloud.test." {
		t.Fatalf("allowed step-up session = %+v", session)
	}
}

func TestAuthenticatedStepUpCompletionShowsSuccessMessage(t *testing.T) {
	manager := NewManager(Config{TrustedStepUpHosts: []string{"pdp.example.test"}}, Dependencies{})
	manager.sessions["auth"] = &sessionState{
		key:               "auth",
		state:             ipc.UserSessionStateAuthenticated,
		agentSessionID:    "sess-1",
		agentSessionToken: "agent-token",
		expiresAt:         time.Now().Add(time.Hour),
	}
	manager.SetAuthenticatedStepUp(
		"Additional security verification is required to access rdp-desktop.trustcloud.test.",
		"https://pdp.example.test/verify/stepup-1",
		"res-rdp",
		"rdp-desktop.trustcloud.test",
		time.Now().Add(time.Minute),
	)

	manager.MarkAuthenticatedStepUpCompleted("sess-1", "res-rdp", "")

	session := manager.sessions["auth"]
	if session.stepUpURL != "" || session.lastError != "" || session.message != "Security verification completed for rdp-desktop.trustcloud.test." {
		t.Fatalf("completed step-up session = %+v", session)
	}
}

func TestAuthenticatedStepUpDeniedKeepsResourceTarget(t *testing.T) {
	manager := NewManager(Config{TrustedStepUpHosts: []string{"pdp.example.test"}}, Dependencies{})
	manager.sessions["auth"] = &sessionState{
		key:               "auth",
		state:             ipc.UserSessionStateAuthenticated,
		agentSessionToken: "agent-token",
		expiresAt:         time.Now().Add(time.Hour),
	}
	manager.SetAuthenticatedStepUp(
		"Additional security verification is required to access ssh.trustcloud.test.",
		"https://pdp.example.test/verify/stepup-2",
		"res-ssh",
		"ssh.trustcloud.test",
		time.Now().Add(time.Minute),
	)

	manager.MarkAuthenticatedResourceDenied("res-ssh", "ssh.trustcloud.test", "verification rejected")

	session := manager.sessions["auth"]
	if session.stepUpURL != "" {
		t.Fatalf("step-up URL should be cleared: %+v", session)
	}
	if session.lastError != "Security verification was rejected for ssh.trustcloud.test. Additional security verification is required to access ssh.trustcloud.test." {
		t.Fatalf("lastError = %q", session.lastError)
	}
}

func TestAuthenticatedStepUpExpirySetsErrorToastMessage(t *testing.T) {
	manager := NewManager(Config{TrustedStepUpHosts: []string{"pdp.example.test"}}, Dependencies{})
	manager.sessions["auth"] = &sessionState{
		key:               "auth",
		state:             ipc.UserSessionStateAuthenticated,
		agentSessionToken: "agent-token",
		expiresAt:         time.Now().Add(time.Hour),
	}
	manager.SetAuthenticatedStepUp(
		"Additional security verification is required to access web-app.trustcloud.test.",
		"https://pdp.example.test/verify/stepup-3",
		"res-web",
		"web-app.trustcloud.test",
		time.Now().Add(20*time.Millisecond),
	)

	deadline := time.After(time.Second)
	for {
		manager.mu.RLock()
		session := manager.sessions["auth"]
		if session.stepUpURL == "" && strings.Contains(session.lastError, "Security verification expired for web-app.trustcloud.test") {
			manager.mu.RUnlock()
			return
		}
		snapshot := *session
		manager.mu.RUnlock()
		select {
		case <-deadline:
			t.Fatalf("step-up did not expire: %+v", snapshot)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestSetFailureUsesFriendlyMessageForMissingWFPDriver(t *testing.T) {
	manager := NewManager(Config{}, Dependencies{})
	manager.sessions["login"] = &sessionState{state: ipc.UserSessionStateAuthenticating}

	manager.setFailure("login", `apply protected resource catalog: apply traffic interception rules: apply WFP redirect rules through \\.\TrustAgentWfp: The system cannot find the file specified.`)

	session := manager.sessions["login"]
	if session.state != ipc.UserSessionStateFailed || session.message != "Authentication failed" {
		t.Fatalf("session failure state = %+v", session)
	}
	if session.lastError != "Local traffic protection is not available. Reinstall TRUSTAgent, then sign in again." {
		t.Fatalf("lastError = %q", session.lastError)
	}
	if strings.Contains(session.lastError, "TrustAgentWfp") || strings.Contains(session.lastError, "apply protected resource catalog") {
		t.Fatalf("lastError should not expose technical WFP details: %q", session.lastError)
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

func TestAuthenticatedSessionRenewalRotatesToken(t *testing.T) {
	client := &recordingSessionClient{
		renew: RenewSessionResponse{
			AgentSessionID:    "sess-renew",
			AgentSessionToken: "agent-token-renewed",
			ExpiresAt:         time.Now().Add(time.Hour),
		},
	}
	manager := NewManager(Config{SessionRenewRetryInterval: 10 * time.Millisecond}, Dependencies{
		Client: client,
		Clock:  time.Now,
	})
	peer := ipc.PeerIdentity{
		UserSID:               "S-1-5-21-1001",
		WindowsLogonSessionID: "00000000:000003e8",
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
		agentSessionID:    "sess-renew",
		agentSessionToken: "agent-token-old",
		expiresAt:         time.Now().Add(80 * time.Millisecond),
	}

	manager.startAuthenticatedSessionExpiryWatcher(key)

	deadline := time.After(time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("session token was not renewed")
		default:
			session, found, err := manager.ActiveAuthenticatedSession()
			if err != nil {
				t.Fatalf("ActiveAuthenticatedSession() error = %v", err)
			}
			if found && session.AgentSessionToken == "agent-token-renewed" {
				if len(client.revokeRequests()) != 0 {
					t.Fatalf("unexpected revoke requests = %+v", client.revokeRequests())
				}
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
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
		message:           "Authenticated",
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
	if snapshot.UserSession.Message != "Authenticated" {
		t.Fatalf("snapshot message = %q, want Authenticated", snapshot.UserSession.Message)
	}
}

type recordingSessionClient struct {
	mu       sync.Mutex
	revokes  []RevokeSessionRequest
	renews   []RenewSessionRequest
	renew    RenewSessionResponse
	renewErr error
	catalog  CatalogResponse
}

func (client *recordingSessionClient) StartSession(context.Context, StartSessionRequest) (StartSessionResponse, error) {
	return StartSessionResponse{}, nil
}

func (client *recordingSessionClient) WatchSessionStatus(context.Context, SessionStatusRequest, func(SessionStatusResponse) bool) error {
	return nil
}

func (client *recordingSessionClient) ClaimSession(context.Context, ClaimSessionRequest) (ClaimSessionResponse, error) {
	return ClaimSessionResponse{}, nil
}

func (client *recordingSessionClient) GetCatalog(context.Context, GetCatalogRequest) (CatalogResponse, error) {
	return client.catalog, nil
}

func (client *recordingSessionClient) RenewSession(_ context.Context, request RenewSessionRequest) (RenewSessionResponse, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.renews = append(client.renews, request)
	return client.renew, client.renewErr
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
