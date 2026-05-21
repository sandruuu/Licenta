package usersession

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"agent/internal/shared/ipc"
)

func NewManager(config Config, dependencies Dependencies) *Manager {
	config = normalizeConfig(config)
	if dependencies.Logger == nil {
		dependencies.Logger = slog.Default()
	}
	if dependencies.Clock == nil {
		dependencies.Clock = time.Now
	}
	return &Manager{
		logger:          dependencies.Logger,
		config:          config,
		client:          dependencies.Client,
		enrollment:      dependencies.Enrollment,
		deviceIdentity:  dependencies.DeviceIdentity,
		postureSnapshot: dependencies.PostureSnapshot,
		clock:           dependencies.Clock,
		sessions:        make(map[string]*sessionState),
	}
}

func normalizeConfig(config Config) Config {
	config.PDPGRPCEndpoint = strings.TrimSpace(config.PDPGRPCEndpoint)
	config.PDPTLSServerName = strings.TrimSpace(config.PDPTLSServerName)
	config.PDPCAFile = strings.TrimSpace(config.PDPCAFile)
	if config.LoginTimeout <= 0 {
		config.LoginTimeout = DefaultTimeout
	}
	if config.LoginPollInterval <= 0 {
		config.LoginPollInterval = DefaultPollInterval
	}
	return config
}

func (manager *Manager) StartInteractive(ctx context.Context, peer ipc.PeerIdentity) (ipc.StartUserLoginInteractiveResponse, string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	key, err := localUserKey(peer)
	if err != nil {
		return ipc.StartUserLoginInteractiveResponse{}, ipc.ErrorCodeInvalidRequest, err
	}
	now := manager.clock().UTC()
	manager.mu.Lock()
	if existing := manager.sessions[key]; existing != nil && existing.state == ipc.UserSessionStateAuthenticating {
		response := ipc.StartUserLoginInteractiveResponse{
			Started:             false,
			AuthURL:             existing.authURL,
			SessionRequestID:    existing.sessionRequestID,
			State:               existing.state,
			Message:             "Authentication is already running",
			ExpiresAt:           existing.expiresAt,
			PollIntervalSeconds: int(existing.pollInterval.Seconds()),
			ReportedAt:          now,
		}
		manager.mu.Unlock()
		return response, "", nil
	}
	manager.mu.Unlock()

	record, err := manager.enrollment.Record(ctx)
	if err != nil {
		return ipc.StartUserLoginInteractiveResponse{}, ipc.ErrorCodeServiceUnavailable, err
	}
	client, err := manager.ensureClient(ctx, record)
	if err != nil {
		return ipc.StartUserLoginInteractiveResponse{}, ipc.ErrorCodeServiceUnavailable, err
	}
	localSIDHash := sidHash(peer.UserSID)
	postureRevision := manager.postureRevision(record.DeviceID)
	start, err := client.StartSession(ctx, StartSessionRequest{
		DeviceID:              record.DeviceID,
		AgentVersion:          "TrustAgent",
		DeviceCertThumbprint:  record.DeviceCertThumbprint,
		PostureRevision:       postureRevision,
		LocalUserSIDHash:      localSIDHash,
		WindowsLogonSessionID: peer.WindowsLogonSessionID,
		WindowsSessionID:      peer.WindowsSessionID,
	})
	if err != nil {
		return ipc.StartUserLoginInteractiveResponse{}, ipc.ErrorCodeServiceUnavailable, err
	}
	if err := validateStartResponse(start); err != nil {
		return ipc.StartUserLoginInteractiveResponse{}, ipc.ErrorCodeInvalidRequest, err
	}
	pollInterval := start.PollInterval
	if pollInterval <= 0 {
		pollInterval = manager.config.LoginPollInterval
	}
	sessionCtx, cancel := context.WithCancel(context.Background())
	state := &sessionState{
		key:              key,
		peer:             peer,
		state:            ipc.UserSessionStateAuthenticating,
		sessionRequestID: start.SessionRequestID,
		claimSecret:      start.ClaimSecret,
		authURL:          start.AuthURL,
		expiresAt:        start.ExpiresAt,
		pollInterval:     pollInterval,
		message:          "Complete login in your browser",
		cancel:           cancel,
	}
	manager.mu.Lock()
	if previous := manager.sessions[key]; previous != nil && previous.cancel != nil {
		previous.cancel()
	}
	manager.sessions[key] = state
	manager.mu.Unlock()
	go manager.runSession(sessionCtx, client, state, localSIDHash, postureRevision)

	return ipc.StartUserLoginInteractiveResponse{
		Started:             true,
		AuthURL:             start.AuthURL,
		SessionRequestID:    start.SessionRequestID,
		State:               ipc.UserSessionStateAuthenticating,
		Message:             "Complete login in your browser",
		ExpiresAt:           start.ExpiresAt,
		PollIntervalSeconds: int(pollInterval.Seconds()),
		ReportedAt:          now,
	}, "", nil
}

func (manager *Manager) Snapshot(peer ipc.PeerIdentity) RuntimeState {
	key, err := localUserKey(peer)
	if err != nil {
		return RuntimeState{UserSession: ipc.UserSessionInfo{State: ipc.UserSessionStateSignedOut}}
	}
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	session := manager.sessions[key]
	if session == nil {
		return RuntimeState{UserSession: ipc.UserSessionInfo{State: ipc.UserSessionStateSignedOut}}
	}
	return RuntimeState{
		UserSession: ipc.UserSessionInfo{
			State:       session.state,
			SessionID:   session.agentSessionID,
			DisplayName: session.displayName,
			Email:       session.email,
			Message:     session.message,
			LastError:   session.lastError,
			ExpiresAt:   session.expiresAt,
		},
		Catalog: session.catalog,
	}
}

func (manager *Manager) Logout(ctx context.Context, peer ipc.PeerIdentity) (ipc.LogoutUserSessionResponse, string, error) {
	key, err := localUserKey(peer)
	if err != nil {
		return ipc.LogoutUserSessionResponse{}, ipc.ErrorCodeInvalidRequest, err
	}
	manager.mu.Lock()
	session := manager.sessions[key]
	delete(manager.sessions, key)
	manager.mu.Unlock()
	if session != nil && session.cancel != nil {
		session.cancel()
	}
	if session != nil && strings.TrimSpace(session.agentSessionToken) != "" {
		if client, err := manager.clientForLogout(ctx); err == nil {
			_ = client.RevokeSession(ctx, RevokeSessionRequest{
				AgentSessionToken: session.agentSessionToken,
				SessionID:         session.agentSessionID,
			})
		}
	}
	return ipc.LogoutUserSessionResponse{LoggedOut: true, State: ipc.UserSessionStateSignedOut, ReportedAt: manager.clock().UTC()}, "", nil
}

func (manager *Manager) runSession(ctx context.Context, client Client, session *sessionState, localSIDHash, postureRevision string) {
	ticker := time.NewTicker(session.pollInterval)
	defer ticker.Stop()
	deadline := session.expiresAt
	if deadline.IsZero() {
		deadline = manager.clock().UTC().Add(manager.config.LoginTimeout)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if manager.clock().UTC().After(deadline) {
				manager.setFailure(session.key, "Authentication request expired")
				return
			}
			if done := manager.pollSession(ctx, client, session, localSIDHash, postureRevision); done {
				return
			}
		}
	}
}

func (manager *Manager) pollSession(ctx context.Context, client Client, session *sessionState, localSIDHash, postureRevision string) bool {
	status, err := client.SessionStatus(ctx, SessionStatusRequest{SessionRequestID: session.sessionRequestID, ClaimSecret: session.claimSecret})
	if err != nil {
		manager.setMessage(session.key, "Waiting for browser authentication status")
		return false
	}
	switch strings.ToUpper(strings.TrimSpace(status.Status)) {
	case StatusWaitingForUserLogin:
		manager.setMessage(session.key, "Waiting for browser login")
		return false
	case StatusReadyToClaim:
		if err := manager.claimSession(ctx, client, session, localSIDHash, postureRevision); err != nil {
			manager.setFailure(session.key, err.Error())
		}
		return true
	case StatusDenied:
		reason := strings.TrimSpace(status.Reason)
		if reason == "" {
			reason = "authentication_failed_or_policy_denied"
		}
		manager.setFailure(session.key, reason)
		return true
	default:
		manager.setMessage(session.key, "Waiting for PDP authentication decision")
		return false
	}
}

func (manager *Manager) claimSession(ctx context.Context, client Client, session *sessionState, localSIDHash, postureRevision string) error {
	claimed, err := client.ClaimSession(ctx, ClaimSessionRequest{
		SessionRequestID:      session.sessionRequestID,
		ClaimSecret:           session.claimSecret,
		PostureRevision:       postureRevision,
		LocalUserSIDHash:      localSIDHash,
		WindowsLogonSessionID: session.peer.WindowsLogonSessionID,
		WindowsSessionID:      session.peer.WindowsSessionID,
	})
	if err != nil {
		return err
	}
	catalog, err := client.GetCatalog(ctx, GetCatalogRequest{AgentSessionToken: claimed.AgentSessionToken})
	if err != nil {
		return err
	}
	manager.mu.Lock()
	current := manager.sessions[session.key]
	if current != nil {
		current.state = ipc.UserSessionStateAuthenticated
		current.agentSessionID = claimed.AgentSessionID
		current.agentSessionToken = claimed.AgentSessionToken
		current.displayName = firstNonEmpty(claimed.DisplayName, claimed.Email)
		current.email = claimed.Email
		current.expiresAt = claimed.ExpiresAt
		current.message = "Authenticated"
		current.lastError = ""
		current.catalog = ipc.CatalogInfo{
			Version:     catalog.Version,
			Resources:   catalog.Resources,
			TTLSeconds:  catalog.TTLSeconds,
			PolicyEpoch: catalog.PolicyEpoch,
			UpdatedAt:   manager.clock().UTC(),
		}
	}
	manager.mu.Unlock()
	return nil
}

func (manager *Manager) setMessage(key, message string) {
	manager.mu.Lock()
	if session := manager.sessions[key]; session != nil && session.state == ipc.UserSessionStateAuthenticating {
		session.message = strings.TrimSpace(message)
	}
	manager.mu.Unlock()
}

func (manager *Manager) setFailure(key, message string) {
	manager.mu.Lock()
	if session := manager.sessions[key]; session != nil {
		session.state = ipc.UserSessionStateFailed
		session.message = "Authentication failed"
		session.lastError = strings.TrimSpace(message)
		if session.cancel != nil {
			session.cancel()
			session.cancel = nil
		}
	}
	manager.mu.Unlock()
}

func (manager *Manager) postureRevision(deviceID string) string {
	if manager.postureSnapshot == nil {
		return ""
	}
	report := manager.postureSnapshot()
	if report.CollectedAt.IsZero() {
		return ""
	}
	return fmt.Sprintf("%s:%d:%d", strings.TrimSpace(deviceID), report.CollectedAt.UTC().Unix(), len(report.Checks))
}

func validateStartResponse(response StartSessionResponse) error {
	if strings.TrimSpace(response.SessionRequestID) == "" {
		return fmt.Errorf("session_request_id is required")
	}
	if strings.TrimSpace(response.AuthURL) == "" || !strings.HasPrefix(strings.ToLower(response.AuthURL), "https://") {
		return fmt.Errorf("auth_url must use https")
	}
	if strings.TrimSpace(response.ClaimSecret) == "" {
		return fmt.Errorf("claim_secret is required")
	}
	if response.ExpiresAt.IsZero() {
		return fmt.Errorf("expires_at is required")
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
