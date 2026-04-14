package admin

import (
	"fmt"
	"log"
	"time"

	"cloud/models"
	"cloud/store"
	"cloud/util"
)

// SessionManager handles active session lifecycle for the Policy Administrator
type SessionManager struct {
	store         *store.Store
	sessionExpiry time.Duration
	maxPerUser    int
}

// NewSessionManager creates a new SessionManager
func NewSessionManager(s *store.Store, expiry time.Duration, maxPerUser int) *SessionManager {
	return &SessionManager{
		store:         s,
		sessionExpiry: expiry,
		maxPerUser:    maxPerUser,
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
		log.Printf("[PA] Revoked oldest session %s for user %s (max reached)", oldest.ID, req.UserID)
	}

	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("generate session ID: %w", err)
	}

	now := time.Now()
	session := &models.Session{
		ID:           sessionID,
		UserID:       req.UserID,
		Username:     req.Username,
		DeviceID:     req.DeviceID,
		SourceIP:     req.SourceIP,
		Resource:     req.Resource,
		Protocol:     req.Protocol,
		RiskScore:    decision.RiskScore,
		CreatedAt:    now,
		ExpiresAt:    now.Add(sm.sessionExpiry),
		LastActivity: now,
	}

	sm.store.SaveSession(session)

	// Record device-user binding (user role — this user accessed via this device)
	if req.DeviceID != "" && req.UserID != "" {
		sm.store.SaveDeviceUser(&models.DeviceUser{
			DeviceID: req.DeviceID,
			UserID:   req.UserID,
			Username: req.Username,
			Role:     "user",
			BoundAt:  now,
		})
	}

	log.Printf("[PA] Session created: %s (user=%s, resource=%s, expires=%s)",
		session.ID, session.Username, session.Resource, session.ExpiresAt.Format(time.RFC3339))

	return session, nil
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
	if !sm.store.RevokeSession(sessionID) {
		return fmt.Errorf("session not found: %s", sessionID)
	}
	log.Printf("[PA] Session revoked: %s", sessionID)
	return nil
}

// ListActiveSessions returns all active sessions
func (sm *SessionManager) ListActiveSessions() []*models.Session {
	return sm.store.ListSessions()
}

// CleanupExpired removes expired sessions
func (sm *SessionManager) CleanupExpired() int {
	count := sm.store.CleanExpiredSessions()
	if count > 0 {
		log.Printf("[PA] Cleaned up %d expired sessions", count)
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
