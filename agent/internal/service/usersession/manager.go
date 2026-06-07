package usersession

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
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
		logger:             dependencies.Logger,
		config:             config,
		client:             dependencies.Client,
		clientFactory:      dependencies.ClientFactory,
		enrollment:         dependencies.Enrollment,
		deviceDataSnapshot: dependencies.DeviceDataSnapshot,
		onCatalog:          dependencies.OnCatalog,
		onLogout:           dependencies.OnLogout,
		clock:              dependencies.Clock,
		sessions:           make(map[string]*sessionState),
		signedOutMessages:  make(map[string]string),
	}
}

func normalizeConfig(config Config) Config {
	if config.LoginTimeout <= 0 {
		config.LoginTimeout = DefaultTimeout
	}
	if config.LoginPollInterval <= 0 {
		config.LoginPollInterval = DefaultPollInterval
	}
	config.TrustedStepUpHosts = normalizeTrustedStepUpHosts(config.TrustedStepUpHosts)
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
	delete(manager.signedOutMessages, key)
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
	deviceDataRevision := manager.deviceDataRevision(record.DeviceID)
	start, err := client.StartSession(ctx, StartSessionRequest{
		DeviceID:              record.DeviceID,
		AgentVersion:          "TrustAgent",
		DeviceCertThumbprint:  record.DeviceCertThumbprint,
		DeviceDataRevision:    deviceDataRevision,
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
		message:          "Open your browser to sign in.",
		cancel:           cancel,
	}
	manager.mu.Lock()
	if previous := manager.sessions[key]; previous != nil {
		clearStepUpLocked(previous)
		if previous.cancel != nil {
			previous.cancel()
		}
	}
	manager.sessions[key] = state
	manager.mu.Unlock()
	go manager.runSession(sessionCtx, client, state, localSIDHash, deviceDataRevision)

	return ipc.StartUserLoginInteractiveResponse{
		Started:             true,
		AuthURL:             start.AuthURL,
		SessionRequestID:    start.SessionRequestID,
		State:               ipc.UserSessionStateAuthenticating,
		Message:             "Open your browser to sign in.",
		ExpiresAt:           start.ExpiresAt,
		PollIntervalSeconds: int(pollInterval.Seconds()),
		ReportedAt:          now,
	}, "", nil
}

func (manager *Manager) Snapshot(peer ipc.PeerIdentity) RuntimeState {
	key, err := localUserKey(peer)
	if err != nil {
		return signedOutRuntime("")
	}
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	return manager.snapshotByKeyLocked(key)
}

func (manager *Manager) DashboardSnapshot(peer ipc.PeerIdentity) RuntimeState {
	key, err := localUserKey(peer)
	if err == nil {
		manager.mu.RLock()
		defer manager.mu.RUnlock()
		return manager.snapshotByKeyLocked(key)
	}
	if !peer.Verified || strings.TrimSpace(peer.UserSID) == "" {
		return signedOutRuntime("")
	}
	now := manager.clock().UTC()
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	var fallback *sessionState
	for _, session := range manager.sessions {
		if !matchesDashboardFallbackSession(session, peer, now) {
			continue
		}
		if fallback != nil {
			return signedOutRuntime("")
		}
		fallback = session
	}
	if fallback == nil {
		return signedOutRuntime("")
	}
	return runtimeForSession(fallback)
}

func (manager *Manager) snapshotByKeyLocked(key string) RuntimeState {
	session := manager.sessions[key]
	if session == nil {
		return signedOutRuntime(manager.signedOutMessages[key])
	}
	return runtimeForSession(session)
}

func runtimeForSession(session *sessionState) RuntimeState {
	return RuntimeState{
		UserSession: ipc.UserSessionInfo{
			State:       session.state,
			SessionID:   session.agentSessionID,
			DisplayName: session.displayName,
			Email:       session.email,
			Message:     session.message,
			LastError:   session.lastError,
			ExpiresAt:   session.expiresAt,
			StepUpURL:   session.stepUpURL,
		},
		Catalog: session.catalog,
	}
}

func signedOutRuntime(message string) RuntimeState {
	return RuntimeState{UserSession: ipc.UserSessionInfo{
		State:   ipc.UserSessionStateSignedOut,
		Message: strings.TrimSpace(message),
	}}
}

func matchesDashboardFallbackSession(session *sessionState, peer ipc.PeerIdentity, now time.Time) bool {
	if session == nil {
		return false
	}
	if session.state != ipc.UserSessionStateAuthenticated && session.state != ipc.UserSessionStateAuthenticating {
		return false
	}
	if !session.expiresAt.IsZero() && now.After(session.expiresAt.UTC()) {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(session.peer.UserSID), strings.TrimSpace(peer.UserSID)) {
		return false
	}
	peerWindowsSessionID := strings.TrimSpace(peer.WindowsSessionID)
	if peerWindowsSessionID != "" && strings.TrimSpace(session.peer.WindowsSessionID) != peerWindowsSessionID {
		return false
	}
	return true
}

func (manager *Manager) ActiveAuthenticatedSession() (AuthenticatedSession, bool, error) {
	if manager == nil {
		return AuthenticatedSession{}, false, nil
	}
	active := manager.ActiveAuthenticatedSessions()
	if len(active) == 0 {
		return AuthenticatedSession{}, false, nil
	}
	if len(active) > 1 {
		return AuthenticatedSession{}, false, fmt.Errorf("multiple authenticated Windows sessions are active")
	}
	return active[0], true, nil
}

func (manager *Manager) ActiveAuthenticatedSessions() []AuthenticatedSession {
	if manager == nil {
		return nil
	}
	now := manager.clock().UTC()
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	active := []AuthenticatedSession{}
	for _, session := range manager.sessions {
		if session == nil || session.state != ipc.UserSessionStateAuthenticated || strings.TrimSpace(session.agentSessionToken) == "" {
			continue
		}
		if !session.expiresAt.IsZero() && now.After(session.expiresAt.UTC()) {
			continue
		}
		active = append(active, AuthenticatedSession{
			AgentSessionID:    session.agentSessionID,
			AgentSessionToken: session.agentSessionToken,
			DisplayName:       session.displayName,
			Email:             session.email,
			ExpiresAt:         session.expiresAt,
			Catalog:           session.catalog,
			Peer:              session.peer,
		})
	}
	return active
}

func (manager *Manager) Logout(ctx context.Context, peer ipc.PeerIdentity) (ipc.LogoutUserSessionResponse, string, error) {
	key, err := localUserKey(peer)
	if err != nil {
		return ipc.LogoutUserSessionResponse{}, ipc.ErrorCodeInvalidRequest, err
	}
	manager.mu.Lock()
	session := manager.sessions[key]
	clearStepUpLocked(session)
	delete(manager.sessions, key)
	delete(manager.signedOutMessages, key)
	manager.mu.Unlock()
	if session != nil && session.cancel != nil {
		session.cancel()
	}
	if session != nil && strings.TrimSpace(session.agentSessionToken) != "" {
		if client, err := manager.clientForLogout(ctx); err == nil {
			if err := client.RevokeSession(ctx, RevokeSessionRequest{
				AgentSessionToken: session.agentSessionToken,
				SessionID:         session.agentSessionID,
			}); err != nil {
				manager.logger.Warn("failed to revoke agent session during logout", "session_id", session.agentSessionID, "error", err)
			}
		} else {
			manager.logger.Warn("failed to create user session client during logout", "session_id", session.agentSessionID, "error", err)
		}
	}
	if manager.onLogout != nil {
		if err := manager.onLogout(ctx, peer); err != nil {
			return ipc.LogoutUserSessionResponse{}, ipc.ErrorCodeServiceUnavailable, err
		}
	}
	return ipc.LogoutUserSessionResponse{LoggedOut: true, State: ipc.UserSessionStateSignedOut, ReportedAt: manager.clock().UTC()}, "", nil
}

func (manager *Manager) RevokeRemote(ctx context.Context, sessionID, message string) bool {
	if manager == nil {
		return false
	}
	sessionID = strings.TrimSpace(sessionID)
	message = firstNonEmpty(message, "Protected resource access was revoked. Sign in again to continue.")
	type revokedSession struct {
		key     string
		peer    ipc.PeerIdentity
		cancel  context.CancelFunc
		session string
	}
	revoked := []revokedSession{}
	manager.mu.Lock()
	for key, session := range manager.sessions {
		if session == nil || session.state != ipc.UserSessionStateAuthenticated {
			continue
		}
		if sessionID != "" && session.agentSessionID != sessionID {
			continue
		}
		clearStepUpLocked(session)
		delete(manager.sessions, key)
		manager.signedOutMessages[key] = message
		revoked = append(revoked, revokedSession{
			key:     key,
			peer:    session.peer,
			cancel:  session.cancel,
			session: session.agentSessionID,
		})
	}
	manager.mu.Unlock()

	for _, item := range revoked {
		if item.cancel != nil {
			item.cancel()
		}
		manager.logger.Info("agent session revoked by PDP event", "session_id", item.session)
		if manager.onLogout != nil {
			if err := manager.onLogout(ctx, item.peer); err != nil {
				manager.logger.Warn("failed to clear protected resources after PDP revocation", "session_id", item.session, "error", err)
			}
		}
	}
	return len(revoked) > 0
}

func (manager *Manager) RefreshCatalog(ctx context.Context, sessionID string) error {
	if manager == nil {
		return nil
	}
	sessionID = strings.TrimSpace(sessionID)
	var token string
	var peer ipc.PeerIdentity
	manager.mu.RLock()
	for _, session := range manager.sessions {
		if session == nil || session.state != ipc.UserSessionStateAuthenticated {
			continue
		}
		if sessionID != "" && session.agentSessionID != sessionID {
			continue
		}
		token = session.agentSessionToken
		peer = session.peer
		sessionID = session.agentSessionID
		break
	}
	manager.mu.RUnlock()
	if strings.TrimSpace(token) == "" {
		return nil
	}
	client, err := manager.clientForLogout(ctx)
	if err != nil {
		return err
	}
	catalog, err := client.GetCatalog(ctx, GetCatalogRequest{AgentSessionToken: token})
	if err != nil {
		return err
	}
	catalogInfo := ipc.CatalogInfo{
		Version:          catalog.Version,
		Resources:        catalog.Resources,
		TTLSeconds:       catalog.TTLSeconds,
		PolicyEpoch:      catalog.PolicyEpoch,
		DeviceDataPolicy: catalog.DeviceDataPolicy,
		UpdatedAt:        manager.clock().UTC(),
	}
	if manager.onCatalog != nil {
		if err := manager.onCatalog(ctx, peer, catalogInfo); err != nil {
			return err
		}
	}
	manager.mu.Lock()
	for _, session := range manager.sessions {
		if session == nil || session.agentSessionID != sessionID || session.state != ipc.UserSessionStateAuthenticated {
			continue
		}
		session.catalog = catalogInfo
		session.message = "Protected resource catalog updated"
	}
	manager.mu.Unlock()
	return nil
}

func (manager *Manager) runSession(ctx context.Context, client Client, session *sessionState, localSIDHash, deviceDataRevision string) {
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
			if done := manager.pollSession(ctx, client, session, localSIDHash, deviceDataRevision); done {
				return
			}
		}
	}
}

func (manager *Manager) pollSession(ctx context.Context, client Client, session *sessionState, localSIDHash, deviceDataRevision string) bool {
	status, err := client.SessionStatus(ctx, SessionStatusRequest{SessionRequestID: session.sessionRequestID, ClaimSecret: session.claimSecret})
	if err != nil {
		manager.setMessage(session.key, "Checking sign-in status...")
		return false
	}
	switch strings.ToUpper(strings.TrimSpace(status.Status)) {
	case StatusWaitingForUserLogin:
		manager.setMessage(session.key, "Sign-in is in progress.")
		return false
	case StatusReadyToClaim:
		if err := manager.claimSession(ctx, client, session, localSIDHash, deviceDataRevision); err != nil {
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
		manager.setMessage(session.key, "Finalizing sign in...")
		return false
	}
}

func (manager *Manager) claimSession(ctx context.Context, client Client, session *sessionState, localSIDHash, deviceDataRevision string) error {
	claimed, err := client.ClaimSession(ctx, ClaimSessionRequest{
		SessionRequestID:      session.sessionRequestID,
		ClaimSecret:           session.claimSecret,
		DeviceDataRevision:    deviceDataRevision,
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
	catalogInfo := ipc.CatalogInfo{
		Version:          catalog.Version,
		Resources:        catalog.Resources,
		TTLSeconds:       catalog.TTLSeconds,
		PolicyEpoch:      catalog.PolicyEpoch,
		DeviceDataPolicy: catalog.DeviceDataPolicy,
		UpdatedAt:        manager.clock().UTC(),
	}
	if manager.onCatalog != nil {
		if err := manager.onCatalog(ctx, session.peer, catalogInfo); err != nil {
			_ = client.RevokeSession(ctx, RevokeSessionRequest{
				AgentSessionToken: claimed.AgentSessionToken,
				SessionID:         claimed.AgentSessionID,
			})
			return fmt.Errorf("apply protected resource catalog: %w", err)
		}
	}
	startExpiryWatcher := false
	manager.mu.Lock()
	current := manager.sessions[session.key]
	if current != nil {
		delete(manager.signedOutMessages, session.key)
		current.state = ipc.UserSessionStateAuthenticated
		current.agentSessionID = claimed.AgentSessionID
		current.agentSessionToken = claimed.AgentSessionToken
		current.displayName = firstNonEmpty(claimed.DisplayName, claimed.Email)
		current.email = claimed.Email
		current.expiresAt = claimed.ExpiresAt
		current.message = "Authenticated"
		current.lastError = ""
		clearStepUpLocked(current)
		current.catalog = catalogInfo
		startExpiryWatcher = true
	}
	manager.mu.Unlock()
	if startExpiryWatcher {
		manager.startAuthenticatedSessionExpiryWatcher(session.key)
	}
	return nil
}

func (manager *Manager) startAuthenticatedSessionExpiryWatcher(key string) {
	if manager == nil {
		return
	}
	manager.mu.Lock()
	session := manager.sessions[key]
	if session == nil || session.state != ipc.UserSessionStateAuthenticated || strings.TrimSpace(session.agentSessionToken) == "" || session.expiresAt.IsZero() {
		manager.mu.Unlock()
		return
	}
	if session.cancel != nil {
		session.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	session.cancel = cancel
	sessionID := session.agentSessionID
	sessionToken := session.agentSessionToken
	peer := session.peer
	expiresAt := session.expiresAt
	manager.mu.Unlock()

	go manager.expireAuthenticatedSession(ctx, key, sessionID, sessionToken, peer, expiresAt)
}

func (manager *Manager) expireAuthenticatedSession(ctx context.Context, key, sessionID, sessionToken string, peer ipc.PeerIdentity, expiresAt time.Time) {
	wait := manager.authenticatedSessionExpiryWait(expiresAt)
	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}

	manager.mu.Lock()
	session := manager.sessions[key]
	if session == nil || session.state != ipc.UserSessionStateAuthenticated || session.agentSessionID != sessionID {
		manager.mu.Unlock()
		return
	}
	delete(manager.sessions, key)
	clearStepUpLocked(session)
	manager.signedOutMessages[key] = "Your session expired. Sign in again to access protected resources."
	manager.mu.Unlock()

	manager.logger.Info("agent session expired; signing out", "session_id", sessionID)
	revokeCtx, cancel := context.WithTimeout(context.Background(), DefaultExpiryRevokeTimeout)
	defer cancel()
	if strings.TrimSpace(sessionToken) != "" {
		if client, err := manager.clientForLogout(revokeCtx); err == nil {
			if err := client.RevokeSession(revokeCtx, RevokeSessionRequest{
				AgentSessionToken: sessionToken,
				SessionID:         sessionID,
			}); err != nil {
				manager.logger.Warn("failed to revoke expired agent session", "session_id", sessionID, "error", err)
			}
		} else {
			manager.logger.Warn("failed to create user session client for expiry cleanup", "session_id", sessionID, "error", err)
		}
	}
	if manager.onLogout != nil {
		if err := manager.onLogout(context.Background(), peer); err != nil {
			manager.logger.Warn("failed to clear protected resources after session expiry", "session_id", sessionID, "error", err)
		}
	}
}

func (manager *Manager) authenticatedSessionExpiryWait(expiresAt time.Time) time.Duration {
	now := manager.clock().UTC()
	remaining := expiresAt.UTC().Sub(now)
	if remaining <= 0 {
		return 0
	}
	lead := DefaultExpiryRevokeLead
	if maxLead := remaining / 10; maxLead < lead {
		lead = maxLead
	}
	wait := remaining - lead
	if wait < 0 {
		return 0
	}
	return wait
}

func (manager *Manager) setMessage(key, message string) {
	manager.mu.Lock()
	if session := manager.sessions[key]; session != nil && session.state == ipc.UserSessionStateAuthenticating {
		session.message = strings.TrimSpace(message)
	}
	manager.mu.Unlock()
}

func (manager *Manager) SetAuthenticatedMessage(message string) {
	if manager == nil {
		return
	}
	message = strings.TrimSpace(message)
	manager.mu.Lock()
	defer manager.mu.Unlock()
	for _, session := range manager.sessions {
		if session == nil || session.state != ipc.UserSessionStateAuthenticated {
			continue
		}
		session.message = message
		session.lastError = ""
		clearStepUpLocked(session)
	}
}

func (manager *Manager) SetAuthenticatedStepUp(message, url, resourceID, target string, expiresAt time.Time) {
	if manager == nil {
		return
	}
	message = strings.TrimSpace(message)
	url = strings.TrimSpace(url)
	if !manager.validStepUpURL(url) {
		manager.logger.Warn("ignoring untrusted step-up URL", "url", url)
		return
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	for _, session := range manager.sessions {
		if session == nil || session.state != ipc.UserSessionStateAuthenticated {
			continue
		}
		clearStepUpLocked(session)
		session.message = firstNonEmpty(message, "Additional verification is required to access this resource.")
		session.lastError = ""
		session.stepUpURL = url
		session.stepUpResourceID = strings.TrimSpace(resourceID)
		session.stepUpTarget = firstNonEmpty(target, resourceID, "this resource")
		session.stepUpExpiresAt = expiresAt.UTC()
		if !expiresAt.IsZero() {
			session.stepUpCancel = manager.startStepUpExpiryWatcherLocked(session.key, url, expiresAt)
		}
	}
}

func (manager *Manager) validStepUpURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return false
	}
	if !strings.HasPrefix(parsed.EscapedPath(), "/browser/step-up/") {
		return false
	}
	if len(manager.config.TrustedStepUpHosts) == 0 {
		return true
	}
	host := strings.ToLower(parsed.Hostname())
	hostPort := strings.ToLower(parsed.Host)
	for _, trusted := range manager.config.TrustedStepUpHosts {
		if trusted == host || trusted == hostPort {
			return true
		}
	}
	return false
}

func normalizeTrustedStepUpHosts(hosts []string) []string {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(hosts))
	for _, host := range hosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			continue
		}
		if parsed, err := url.Parse(host); err == nil && parsed.Host != "" {
			host = strings.ToLower(parsed.Hostname())
			if parsed.Port() != "" {
				host = strings.ToLower(parsed.Host)
			}
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		normalized = append(normalized, host)
	}
	return normalized
}

func (manager *Manager) ClearAuthenticatedStepUp() {
	if manager == nil {
		return
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	for _, session := range manager.sessions {
		if session == nil || session.state != ipc.UserSessionStateAuthenticated {
			continue
		}
		if strings.TrimSpace(session.stepUpURL) != "" {
			clearStepUpLocked(session)
			session.message = "Authenticated"
		}
	}
}

func (manager *Manager) MarkAuthenticatedStepUpAllowed(resourceID, target string) {
	if manager == nil {
		return
	}
	resourceID = strings.TrimSpace(resourceID)
	target = strings.TrimSpace(target)
	manager.mu.Lock()
	defer manager.mu.Unlock()
	for _, session := range manager.sessions {
		if session == nil || session.state != ipc.UserSessionStateAuthenticated || strings.TrimSpace(session.stepUpURL) == "" {
			continue
		}
		if !stepUpMatches(session, resourceID, target) {
			continue
		}
		displayTarget := stepUpDisplayTarget(session, resourceID, target)
		clearStepUpLocked(session)
		session.lastError = ""
		session.message = "Access granted to " + displayTarget + "."
	}
}

func (manager *Manager) MarkAuthenticatedResourceDenied(resourceID, target, reason string) {
	if manager == nil {
		return
	}
	resourceID = strings.TrimSpace(resourceID)
	target = strings.TrimSpace(target)
	reason = strings.TrimSpace(reason)
	manager.mu.Lock()
	defer manager.mu.Unlock()
	for _, session := range manager.sessions {
		if session == nil || session.state != ipc.UserSessionStateAuthenticated {
			continue
		}
		displayTarget := firstNonEmpty(target, resourceID, "this resource")
		if strings.TrimSpace(session.stepUpURL) != "" && stepUpMatches(session, resourceID, target) {
			displayTarget = stepUpDisplayTarget(session, resourceID, target)
			clearStepUpLocked(session)
			session.message = "Authenticated"
			session.lastError = securityVerificationFailedMessage(displayTarget, reason)
			continue
		}
		session.lastError = resourceAccessDeniedMessage(displayTarget, reason)
	}
}

func (manager *Manager) setFailure(key, message string) {
	originalMessage := strings.TrimSpace(message)
	displayMessage := userSessionFailureMessage(originalMessage)
	if displayMessage != originalMessage && manager != nil && manager.logger != nil {
		manager.logger.Warn("agent authentication failed because local traffic protection is unavailable", "error", originalMessage)
	}

	manager.mu.Lock()
	if session := manager.sessions[key]; session != nil {
		session.state = ipc.UserSessionStateFailed
		session.message = "Authentication failed"
		session.lastError = displayMessage
		clearStepUpLocked(session)
		if session.cancel != nil {
			session.cancel()
			session.cancel = nil
		}
	}
	manager.mu.Unlock()
}

func (manager *Manager) startStepUpExpiryWatcherLocked(key, url string, expiresAt time.Time) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())
	wait := time.Until(expiresAt.UTC())
	if wait < 0 {
		wait = 0
	}
	go func() {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		manager.markStepUpExpired(key, url)
	}()
	return cancel
}

func (manager *Manager) markStepUpExpired(key, url string) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	session := manager.sessions[key]
	if session == nil || session.state != ipc.UserSessionStateAuthenticated || strings.TrimSpace(session.stepUpURL) != strings.TrimSpace(url) {
		return
	}
	target := stepUpDisplayTarget(session, "", "")
	clearStepUpLocked(session)
	session.message = "Authenticated"
	session.lastError = securityVerificationExpiredMessage(target)
}

func clearStepUpLocked(session *sessionState) {
	if session == nil {
		return
	}
	if session.stepUpCancel != nil {
		session.stepUpCancel()
		session.stepUpCancel = nil
	}
	session.stepUpURL = ""
	session.stepUpResourceID = ""
	session.stepUpTarget = ""
	session.stepUpExpiresAt = time.Time{}
}

func stepUpMatches(session *sessionState, resourceID, target string) bool {
	if session == nil {
		return false
	}
	resourceID = strings.TrimSpace(resourceID)
	target = strings.TrimSpace(target)
	if resourceID != "" && strings.TrimSpace(session.stepUpResourceID) != "" {
		return strings.EqualFold(resourceID, strings.TrimSpace(session.stepUpResourceID))
	}
	if target != "" && strings.TrimSpace(session.stepUpTarget) != "" {
		return strings.EqualFold(target, strings.TrimSpace(session.stepUpTarget))
	}
	return true
}

func stepUpDisplayTarget(session *sessionState, resourceID, target string) string {
	if session == nil {
		return firstNonEmpty(target, resourceID, "this resource")
	}
	return firstNonEmpty(target, session.stepUpTarget, resourceID, session.stepUpResourceID, "this resource")
}

func securityVerificationExpiredMessage(target string) string {
	target = firstNonEmpty(target, "this resource")
	return "Security verification expired for " + target + ". Additional security verification is required to access " + target + "."
}

func securityVerificationFailedMessage(target, reason string) string {
	target = firstNonEmpty(target, "this resource")
	reason = strings.ToLower(strings.TrimSpace(reason))
	switch {
	case strings.Contains(reason, "expired"):
		return securityVerificationExpiredMessage(target)
	case strings.Contains(reason, "cancelled"), strings.Contains(reason, "canceled"), strings.Contains(reason, "abort"):
		return "Security verification was canceled for " + target + ". Additional security verification is required to access " + target + "."
	case strings.Contains(reason, "denied"), strings.Contains(reason, "reject"), strings.Contains(reason, "failed"):
		return "Security verification was rejected for " + target + ". Additional security verification is required to access " + target + "."
	default:
		return "Security verification was not completed for " + target + ". Additional security verification is required to access " + target + "."
	}
}

func resourceAccessDeniedMessage(target, reason string) string {
	target = firstNonEmpty(target, "this resource")
	if strings.TrimSpace(reason) == "" {
		return "Access to " + target + " was denied."
	}
	return "Access to " + target + " was denied. " + strings.TrimSpace(reason)
}

func userSessionFailureMessage(message string) string {
	if isLocalTrafficProtectionUnavailable(message) {
		return "Local traffic protection is not available. Reinstall TRUSTAgent, then sign in again."
	}
	return strings.TrimSpace(message)
}

func isLocalTrafficProtectionUnavailable(message string) bool {
	normalized := strings.ToLower(strings.TrimSpace(message))
	if normalized == "" {
		return false
	}
	if strings.Contains(normalized, "trustagentwfp") {
		return true
	}
	if strings.Contains(normalized, "wfp redirect rules") {
		return true
	}
	return strings.Contains(normalized, "apply traffic interception rules") &&
		strings.Contains(normalized, "system cannot find the file specified")
}

func (manager *Manager) deviceDataRevision(deviceID string) string {
	if manager.deviceDataSnapshot == nil {
		return ""
	}
	report := manager.deviceDataSnapshot()
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
