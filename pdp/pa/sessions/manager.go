package sessions

import (
	"fmt"
	"log"
	"strings"
	"time"

	"pdp/models"
	"pdp/store"
	"pdp/util"
)

// SessionManager handles active session lifecycle for the Policy Administrator
type SessionManager struct {
	store         *store.Store
	sessionExpiry time.Duration
	maxPerUser    int
	onDeleted     func(session *models.Session, reason string)
}

// NewSessionManager creates a new SessionManager
func NewSessionManager(s *store.Store, expiry time.Duration, maxPerUser int) *SessionManager {
	return &SessionManager{
		store:         s,
		sessionExpiry: expiry,
		maxPerUser:    maxPerUser,
	}
}

// SetDeleteEventSink wires server-side session deletion notifications into
// PA-owned revocation flows.
func (sm *SessionManager) SetDeleteEventSink(fn func(session *models.Session, reason string)) {
	sm.onDeleted = fn
}

func (sm *SessionManager) publishDeleted(session *models.Session, reason string) {
	if sm.onDeleted != nil && session != nil {
		sm.onDeleted(session, reason)
	}
}

// CreateSession creates a new authorized session after successful policy evaluation
func (sm *SessionManager) CreateSession(decision *models.AccessDecision, req models.AccessRequest) (*models.Session, error) {
	// Check max sessions per user
	userSessions := sm.store.ListUserSessions(req.UserID)
	if len(userSessions) >= sm.maxPerUser {
		// Revoke the oldest session
		oldest := userSessions[0]
		for _, s := range userSessions[1:] {
			if s.CreatedAt.Before(oldest.CreatedAt) {
				oldest = s
			}
		}
		sm.store.RevokeSession(oldest.ID)
		sm.publishDeleted(oldest, "max_sessions_exceeded")
		log.Printf("[PA] Revoked oldest session %s for user %s (max reached)", oldest.ID, req.UserID)
	}

	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("generate session ID: %w", err)
	}

	now := time.Now()
	session := &models.Session{
		ID:             sessionID,
		UserID:         req.UserID,
		Username:       req.Username,
		DeviceID:       req.DeviceID,
		SourceIP:       req.SourceIP,
		Resource:       req.Resource,
		GatewayID:      req.GatewayID,
		Protocol:       req.Protocol,
		RiskScore:      decision.RiskScore,
		OrganizationID: req.OrganizationID,
		CreatedAt:      now,
		LastActivity:   now,
	}
	sm.applyDecisionSessionState(session, decision, now, true)

	sm.store.SaveSession(session)

	// Record device-user binding (user role — this user accessed via this device)
	sm.saveDeviceUserBinding(req, now)

	log.Printf("[PA] Session created: %s (user=%s, resource=%s, expires=%s)",
		session.ID, session.Username, session.Resource, session.ExpiresAt.Format(time.RFC3339))

	return session, nil
}

// CreateOrRenewSession reuses the active PA resource session for the same
// user/device/resource tuple. When the session is close to expiry, it extends
// the lifetime instead of creating a second session for another TCP flow.
func (sm *SessionManager) CreateOrRenewSession(decision *models.AccessDecision, req models.AccessRequest, renewBefore time.Duration) (*models.Session, bool, error) {
	if sm == nil || sm.store == nil {
		return nil, false, fmt.Errorf("session manager is not available")
	}
	now := time.Now()
	if session := sm.findReusableSession(req, now); session != nil {
		if sm.shouldRevokeForRiskIncrease(session, decision) {
			sm.revokeSessionSnapshot(session, "risk_increased")
			session, err := sm.CreateSession(decision, req)
			return session, false, err
		}
		session.Username = req.Username
		session.SourceIP = req.SourceIP
		session.LastActivity = now
		previousExpiresAt := session.ExpiresAt
		sm.applyDecisionSessionState(session, decision, now, false)
		if decision != nil {
			session.RiskScore = decision.RiskScore
		}
		if renewBefore < 0 {
			renewBefore = 0
		}
		nextExpiresAt := sm.nextSessionExpiry(session, now)
		if !previousExpiresAt.After(now.Add(renewBefore)) || nextExpiresAt.Before(previousExpiresAt) {
			session.ExpiresAt = nextExpiresAt
			log.Printf("[PA] Session renewed: %s (user=%s, resource=%s, expires=%s)",
				session.ID, session.Username, session.Resource, session.ExpiresAt.Format(time.RFC3339))
		} else {
			session.ExpiresAt = previousExpiresAt
			log.Printf("[PA] Session reused: %s (user=%s, resource=%s, expires=%s)",
				session.ID, session.Username, session.Resource, session.ExpiresAt.Format(time.RFC3339))
		}
		sm.store.SaveSession(session)
		sm.saveDeviceUserBinding(req, now)
		return session, true, nil
	}
	session, err := sm.CreateSession(decision, req)
	return session, false, err
}

func (sm *SessionManager) findReusableSession(req models.AccessRequest, now time.Time) *models.Session {
	if sm == nil || sm.store == nil {
		return nil
	}
	var best *models.Session
	for _, session := range sm.store.ListSessions() {
		if session == nil || session.Revoked || !session.ExpiresAt.After(now) {
			continue
		}
		if !sameResourceSessionSubject(session, req) {
			continue
		}
		if best == nil || session.ExpiresAt.After(best.ExpiresAt) {
			best = session
		}
	}
	return best
}

func (sm *SessionManager) applyDecisionSessionState(session *models.Session, decision *models.AccessDecision, now time.Time, forceExpiry bool) {
	if session == nil {
		return
	}
	if decision != nil {
		session.PolicyID = strings.TrimSpace(decision.MatchedRule)
		session.RiskScore = decision.RiskScore
		controls := normalizedSessionControls(decision.SessionControls)
		session.SessionMaxAgeSeconds = controls.MaxAgeSeconds
		session.RevalidateEverySeconds = controls.RevalidateEverySeconds
		session.RevokeOnPostureChange = controls.RevokeOnPostureChange
		session.RevokeOnRiskIncrease = controls.RevokeOnRiskIncrease
	}
	if session.RevalidateEverySeconds > 0 {
		session.RevalidateAfter = now.Add(time.Duration(session.RevalidateEverySeconds) * time.Second)
	} else {
		session.RevalidateAfter = time.Time{}
	}
	if forceExpiry || session.ExpiresAt.IsZero() {
		session.ExpiresAt = sm.nextSessionExpiry(session, now)
	}
}

func normalizedSessionControls(controls models.SessionPolicyControls) models.SessionPolicyControls {
	if controls.MaxAgeSeconds < 0 {
		controls.MaxAgeSeconds = 0
	}
	if controls.RevalidateEverySeconds < 0 {
		controls.RevalidateEverySeconds = 0
	}
	return controls
}

func (sm *SessionManager) nextSessionExpiry(session *models.Session, now time.Time) time.Time {
	if now.IsZero() {
		now = time.Now()
	}
	expiresAt := now.Add(sm.sessionExpiry)
	if session == nil {
		return expiresAt
	}
	createdAt := session.CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}
	if session.SessionMaxAgeSeconds > 0 {
		maxExpiresAt := createdAt.Add(time.Duration(session.SessionMaxAgeSeconds) * time.Second)
		if maxExpiresAt.Before(expiresAt) {
			expiresAt = maxExpiresAt
		}
	}
	if session.RevalidateEverySeconds > 0 {
		revalidateExpiresAt := now.Add(time.Duration(session.RevalidateEverySeconds) * time.Second)
		if revalidateExpiresAt.Before(expiresAt) {
			expiresAt = revalidateExpiresAt
		}
	}
	return expiresAt
}

func (sm *SessionManager) shouldRevokeForRiskIncrease(session *models.Session, decision *models.AccessDecision) bool {
	if session == nil || decision == nil {
		return false
	}
	controls := normalizedSessionControls(decision.SessionControls)
	if !session.RevokeOnRiskIncrease && !controls.RevokeOnRiskIncrease {
		return false
	}
	return decision.RiskScore > session.RiskScore
}

func (sm *SessionManager) revokeSessionSnapshot(session *models.Session, reason string) bool {
	if sm == nil || sm.store == nil || session == nil {
		return false
	}
	if !sm.store.RevokeSession(session.ID) {
		return false
	}
	session.Revoked = true
	sm.publishDeleted(session, reason)
	log.Printf("[PA] Session revoked: %s reason=%s user=%s device=%s resource=%s gateway=%s",
		session.ID, reason, session.UserID, session.DeviceID, session.Resource, session.GatewayID)
	return true
}

func sameResourceSessionSubject(session *models.Session, req models.AccessRequest) bool {
	if session == nil {
		return false
	}
	return strings.TrimSpace(session.UserID) == strings.TrimSpace(req.UserID) &&
		strings.TrimSpace(session.DeviceID) == strings.TrimSpace(req.DeviceID) &&
		strings.TrimSpace(session.Resource) == strings.TrimSpace(req.Resource) &&
		strings.TrimSpace(session.GatewayID) == strings.TrimSpace(req.GatewayID) &&
		strings.EqualFold(strings.TrimSpace(session.Protocol), strings.TrimSpace(req.Protocol)) &&
		strings.TrimSpace(session.OrganizationID) == strings.TrimSpace(req.OrganizationID)
}

func (sm *SessionManager) saveDeviceUserBinding(req models.AccessRequest, now time.Time) {
	if sm == nil || sm.store == nil || strings.TrimSpace(req.DeviceID) == "" || strings.TrimSpace(req.UserID) == "" {
		return
	}
	sm.store.SaveDeviceUser(&models.DeviceUser{
		DeviceID: strings.TrimSpace(req.DeviceID),
		UserID:   strings.TrimSpace(req.UserID),
		Username: req.Username,
		Role:     "user",
		BoundAt:  now,
	})
}

// ValidateSession checks if a session is still valid (not expired, not revoked)
func (sm *SessionManager) ValidateSession(sessionID string) (*models.Session, error) {
	session, exists := sm.store.GetSession(sessionID)
	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	if session.Revoked {
		return nil, fmt.Errorf("session has been revoked")
	}

	if session.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("session has expired")
	}

	// Update last activity
	session.LastActivity = time.Now()
	sm.store.SaveSession(session)

	return session, nil
}

// RevokeSession terminates an active session
func (sm *SessionManager) RevokeSession(sessionID string) error {
	session, _ := sm.store.GetSession(sessionID)
	if !sm.store.RevokeSession(sessionID) {
		return fmt.Errorf("session not found: %s", sessionID)
	}
	sm.publishDeleted(session, "admin_revoked")
	log.Printf("[PA] Session revoked: %s", sessionID)
	return nil
}

// RevokeSessionsMatching terminates every active session accepted by the
// predicate. All revocations pass through the delete sink so Gateway-side
// provisioned sessions and active relays are cut consistently.
func (sm *SessionManager) RevokeSessionsMatching(reason string, match func(*models.Session) bool) int {
	if sm == nil || sm.store == nil || match == nil {
		return 0
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "policy_updated"
	}

	revoked := 0
	for _, session := range sm.store.ListSessions() {
		if session == nil || session.Revoked || !match(session) {
			continue
		}
		if !sm.store.RevokeSession(session.ID) {
			continue
		}
		revoked++
		sm.publishDeleted(session, reason)
		log.Printf("[PA] Session revoked: %s reason=%s user=%s device=%s resource=%s gateway=%s",
			session.ID, reason, session.UserID, session.DeviceID, session.Resource, session.GatewayID)
	}
	return revoked
}

// RevokeSessionsForDeviceUser terminates all active resource sessions owned by
// a user on a specific enrolled device. Organization is optional but used when present
// to avoid crossing organization boundaries during Agent logout.
func (sm *SessionManager) RevokeSessionsForDeviceUser(userID, deviceID, organizationID, reason string) int {
	if sm == nil || sm.store == nil {
		return 0
	}
	userID = strings.TrimSpace(userID)
	deviceID = strings.TrimSpace(deviceID)
	organizationID = strings.TrimSpace(organizationID)
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "agent_logout"
	}
	if userID == "" || deviceID == "" {
		return 0
	}

	revoked := 0
	for _, session := range sm.store.ListSessions() {
		if session == nil || session.Revoked {
			continue
		}
		if strings.TrimSpace(session.UserID) != userID || strings.TrimSpace(session.DeviceID) != deviceID {
			continue
		}
		if organizationID != "" && strings.TrimSpace(session.OrganizationID) != organizationID {
			continue
		}
		if !sm.store.RevokeSession(session.ID) {
			continue
		}
		revoked++
		sm.publishDeleted(session, reason)
		log.Printf("[PA] Session revoked on agent logout: %s (user=%s device=%s)", session.ID, userID, deviceID)
	}
	return revoked
}

// RevokeSessionsForDevice terminates all active resource sessions issued to a
// device. Organization is optional and narrows the revocation to one organization.
func (sm *SessionManager) RevokeSessionsForDevice(deviceID, organizationID, reason string) int {
	deviceID = strings.TrimSpace(deviceID)
	organizationID = strings.TrimSpace(organizationID)
	if deviceID == "" {
		return 0
	}
	return sm.RevokeSessionsMatching(reason, func(session *models.Session) bool {
		if strings.TrimSpace(session.DeviceID) != deviceID {
			return false
		}
		return organizationID == "" || strings.TrimSpace(session.OrganizationID) == organizationID
	})
}

// RevokeSessionsForResource terminates all active sessions for a protected
// resource. Organization is optional and narrows the revocation to one organization.
func (sm *SessionManager) RevokeSessionsForResource(resourceID, organizationID, reason string) int {
	resourceID = strings.TrimSpace(resourceID)
	organizationID = strings.TrimSpace(organizationID)
	if resourceID == "" {
		return 0
	}
	return sm.RevokeSessionsMatching(reason, func(session *models.Session) bool {
		if strings.TrimSpace(session.Resource) != resourceID {
			return false
		}
		return organizationID == "" || strings.TrimSpace(session.OrganizationID) == organizationID
	})
}

// RevokeSessionsForGateway terminates all active sessions provisioned through a
// gateway. Organization is optional and narrows the revocation to one organization.
func (sm *SessionManager) RevokeSessionsForGateway(gatewayID, organizationID, reason string) int {
	gatewayID = strings.TrimSpace(gatewayID)
	organizationID = strings.TrimSpace(organizationID)
	if gatewayID == "" {
		return 0
	}
	return sm.RevokeSessionsMatching(reason, func(session *models.Session) bool {
		if strings.TrimSpace(session.GatewayID) != gatewayID {
			return false
		}
		return organizationID == "" || strings.TrimSpace(session.OrganizationID) == organizationID
	})
}

// RevokeSessionsForOrganization terminates all active sessions in an organization. It is a
// conservative fallback for policy changes whose blast radius cannot be narrowed
// to a resource, device, user, or gateway.
func (sm *SessionManager) RevokeSessionsForOrganization(organizationID, reason string) int {
	organizationID = strings.TrimSpace(organizationID)
	if organizationID == "" {
		return 0
	}
	return sm.RevokeSessionsMatching(reason, func(session *models.Session) bool {
		return strings.TrimSpace(session.OrganizationID) == organizationID
	})
}

// ListActiveSessions returns all active sessions
func (sm *SessionManager) ListActiveSessions() []*models.Session {
	return sm.store.ListSessions()
}

// CleanupExpired removes expired sessions
func (sm *SessionManager) CleanupExpired() int {
	expired, count := sm.store.CleanExpiredSessionsWithSnapshot(time.Now())
	if count > 0 {
		log.Printf("[PA] Cleaned up %d expired sessions", count)
	}
	for _, session := range expired {
		sm.publishDeleted(session, "expired")
	}
	return count
}

// StartCleanupLoop runs periodic session cleanup
func (sm *SessionManager) StartCleanupLoop(interval time.Duration, stopChan <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				sm.CleanupExpired()
			}
		}
	}()
}

// generateSessionID creates a unique session ID
func generateSessionID() (string, error) {
	return util.GenerateID("sess")
}
