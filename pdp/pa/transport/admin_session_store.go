package transport

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"pdp/models"
	paauth "pdp/pa/auth"
	"pdp/runtime/redisstate"
	"pdp/util"
)

const (
	adminSessionStateKind      = "admin_dashboard_session"
	adminSessionRefreshBytes   = 32
	adminSessionLockTTL        = 5 * time.Second
	adminSessionLockWait       = 5 * time.Second
	defaultAdminAccessTokenTTL = 5 * time.Minute
	defaultAdminSessionIdleTTL = 30 * time.Minute
	defaultAdminSessionAbsTTL  = 8 * time.Hour
)

var (
	errAdminSessionNotFound        = errors.New("admin session not found")
	errAdminSessionExpired         = errors.New("admin session expired")
	errAdminSessionRefreshMismatch = errors.New("admin refresh token mismatch")
)

type adminSessionRecord struct {
	ID                string    `json:"id"`
	UserID            string    `json:"user_id"`
	Username          string    `json:"username"`
	Role              string    `json:"role"`
	RefreshTokenHash  string    `json:"refresh_token_hash"`
	CreatedAt         time.Time `json:"created_at"`
	LastActivity      time.Time `json:"last_activity"`
	IdleExpiresAt     time.Time `json:"idle_expires_at"`
	AbsoluteExpiresAt time.Time `json:"absolute_expires_at"`
	RevokedAt         time.Time `json:"revoked_at,omitempty"`
}

type adminSessionStore struct {
	state       *redisstate.Client
	accessTTL   time.Duration
	idleTTL     time.Duration
	absoluteTTL time.Duration
}

func newAdminSessionStore(state *redisstate.Client, accessTTL, idleTTL, absoluteTTL time.Duration) *adminSessionStore {
	if accessTTL <= 0 {
		accessTTL = defaultAdminAccessTokenTTL
	}
	if idleTTL <= 0 {
		idleTTL = defaultAdminSessionIdleTTL
	}
	if absoluteTTL <= 0 {
		absoluteTTL = defaultAdminSessionAbsTTL
	}
	if absoluteTTL < idleTTL {
		idleTTL = absoluteTTL
	}
	return &adminSessionStore{
		state:       state,
		accessTTL:   accessTTL,
		idleTTL:     idleTTL,
		absoluteTTL: absoluteTTL,
	}
}

func (store *adminSessionStore) create(user *models.User) (*adminSessionRecord, string, error) {
	if store == nil || store.state == nil {
		return nil, "", redisstate.ErrUnavailable
	}
	if user == nil || strings.TrimSpace(user.ID) == "" {
		return nil, "", fmt.Errorf("admin user is required")
	}
	sessionID, err := util.GenerateID("ads")
	if err != nil {
		return nil, "", fmt.Errorf("generate admin session id: %w", err)
	}
	refreshToken, err := randomSessionSecret(adminSessionRefreshBytes)
	if err != nil {
		return nil, "", fmt.Errorf("generate admin refresh token: %w", err)
	}
	now := time.Now().UTC()
	record := &adminSessionRecord{
		ID:                sessionID,
		UserID:            strings.TrimSpace(user.ID),
		Username:          strings.TrimSpace(user.Username),
		Role:              strings.TrimSpace(user.Role),
		RefreshTokenHash:  hashSessionSecret(refreshToken),
		CreatedAt:         now,
		LastActivity:      now,
		IdleExpiresAt:     now.Add(store.idleTTL),
		AbsoluteExpiresAt: now.Add(store.absoluteTTL),
	}
	if err := store.save(record); err != nil {
		return nil, "", err
	}
	return copyAdminSession(record), refreshToken, nil
}

func (store *adminSessionStore) validateAccess(claims *paauth.CustomClaims) (*adminSessionRecord, bool) {
	if store == nil || store.state == nil || claims == nil {
		return nil, false
	}
	sessionID := strings.TrimSpace(claims.SessionID)
	if sessionID == "" {
		return nil, false
	}

	var updated *adminSessionRecord
	err := store.state.WithLock(context.Background(), "admin-session-"+sessionID, adminSessionLockTTL, adminSessionLockWait, func() error {
		session, ok := store.load(sessionID)
		if !ok || session == nil {
			return errAdminSessionNotFound
		}
		now := time.Now().UTC()
		if store.sessionExpired(session, now) {
			_ = store.state.DeleteEphemeralState(adminSessionStateKind, sessionID)
			return errAdminSessionExpired
		}
		if session.UserID != strings.TrimSpace(claims.UserID) || session.Role != strings.TrimSpace(claims.Role) {
			return errAdminSessionNotFound
		}
		session.LastActivity = now
		session.IdleExpiresAt = minTime(now.Add(store.idleTTL), session.AbsoluteExpiresAt)
		if err := store.save(session); err != nil {
			return err
		}
		updated = copyAdminSession(session)
		return nil
	})
	if err != nil || updated == nil {
		return nil, false
	}
	return updated, true
}

func (store *adminSessionStore) refresh(sessionID, refreshToken string, userLookup func(string) (*models.User, bool)) (*adminSessionRecord, string, error) {
	sessionID = strings.TrimSpace(sessionID)
	refreshToken = strings.TrimSpace(refreshToken)
	if store == nil || store.state == nil {
		return nil, "", redisstate.ErrUnavailable
	}
	if sessionID == "" || refreshToken == "" {
		return nil, "", errAdminSessionNotFound
	}

	var refreshed *adminSessionRecord
	var nextRefreshToken string
	err := store.state.WithLock(context.Background(), "admin-session-"+sessionID, adminSessionLockTTL, adminSessionLockWait, func() error {
		session, ok := store.load(sessionID)
		if !ok || session == nil {
			return errAdminSessionNotFound
		}
		if store.sessionExpired(session, time.Now().UTC()) {
			_ = store.state.DeleteEphemeralState(adminSessionStateKind, sessionID)
			return errAdminSessionExpired
		}
		if subtle.ConstantTimeCompare([]byte(session.RefreshTokenHash), []byte(hashSessionSecret(refreshToken))) != 1 {
			return errAdminSessionRefreshMismatch
		}
		if userLookup != nil {
			user, ok := userLookup(session.UserID)
			if !ok || user == nil || user.Disabled || user.Role != "platform_admin" {
				_ = store.state.DeleteEphemeralState(adminSessionStateKind, sessionID)
				return errAdminSessionExpired
			}
			session.Username = strings.TrimSpace(user.Username)
			session.Role = strings.TrimSpace(user.Role)
		}
		next, err := randomSessionSecret(adminSessionRefreshBytes)
		if err != nil {
			return fmt.Errorf("generate admin refresh token: %w", err)
		}
		now := time.Now().UTC()
		session.RefreshTokenHash = hashSessionSecret(next)
		session.LastActivity = now
		session.IdleExpiresAt = minTime(now.Add(store.idleTTL), session.AbsoluteExpiresAt)
		if err := store.save(session); err != nil {
			return err
		}
		refreshed = copyAdminSession(session)
		nextRefreshToken = next
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return refreshed, nextRefreshToken, nil
}

func (store *adminSessionStore) revoke(sessionID string) bool {
	sessionID = strings.TrimSpace(sessionID)
	if store == nil || store.state == nil || sessionID == "" {
		return false
	}
	_ = store.state.DeleteEphemeralState(adminSessionStateKind, sessionID)
	return true
}

func (store *adminSessionStore) revokeWithRefresh(sessionID, refreshToken string) bool {
	sessionID = strings.TrimSpace(sessionID)
	refreshToken = strings.TrimSpace(refreshToken)
	if store == nil || store.state == nil || sessionID == "" || refreshToken == "" {
		return false
	}
	var revoked bool
	_ = store.state.WithLock(context.Background(), "admin-session-"+sessionID, adminSessionLockTTL, adminSessionLockWait, func() error {
		session, ok := store.load(sessionID)
		if !ok || session == nil {
			return nil
		}
		if subtle.ConstantTimeCompare([]byte(session.RefreshTokenHash), []byte(hashSessionSecret(refreshToken))) != 1 {
			return nil
		}
		_ = store.state.DeleteEphemeralState(adminSessionStateKind, sessionID)
		revoked = true
		return nil
	})
	return revoked
}

func (store *adminSessionStore) accessTokenTTL(session *adminSessionRecord) time.Duration {
	if store == nil || session == nil {
		return 0
	}
	now := time.Now().UTC()
	ttl := store.accessTTL
	if ttl <= 0 {
		ttl = defaultAdminAccessTokenTTL
	}
	untilIdle := session.IdleExpiresAt.Sub(now)
	untilAbsolute := session.AbsoluteExpiresAt.Sub(now)
	ttl = minDuration(ttl, untilIdle)
	ttl = minDuration(ttl, untilAbsolute)
	if ttl < time.Second {
		return 0
	}
	return ttl
}

func (store *adminSessionStore) save(session *adminSessionRecord) error {
	if store == nil || store.state == nil {
		return redisstate.ErrUnavailable
	}
	raw, err := json.Marshal(session)
	if err != nil {
		return err
	}
	return store.state.SaveEphemeralState(adminSessionStateKind, session.ID, raw, minTime(session.IdleExpiresAt, session.AbsoluteExpiresAt))
}

func (store *adminSessionStore) load(sessionID string) (*adminSessionRecord, bool) {
	if store == nil || store.state == nil || strings.TrimSpace(sessionID) == "" {
		return nil, false
	}
	raw, ok := store.state.GetEphemeralState(adminSessionStateKind, sessionID)
	if !ok {
		return nil, false
	}
	var session adminSessionRecord
	if err := json.Unmarshal(raw, &session); err != nil {
		_ = store.state.DeleteEphemeralState(adminSessionStateKind, sessionID)
		return nil, false
	}
	return &session, true
}

func (store *adminSessionStore) sessionExpired(session *adminSessionRecord, now time.Time) bool {
	return session == nil ||
		!session.RevokedAt.IsZero() ||
		(!session.IdleExpiresAt.IsZero() && !now.Before(session.IdleExpiresAt)) ||
		(!session.AbsoluteExpiresAt.IsZero() && !now.Before(session.AbsoluteExpiresAt))
}

func copyAdminSession(session *adminSessionRecord) *adminSessionRecord {
	if session == nil {
		return nil
	}
	copy := *session
	return &copy
}

func minDuration(a, b time.Duration) time.Duration {
	if a <= 0 {
		return b
	}
	if b <= 0 || a < b {
		return a
	}
	return b
}

func minTime(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() || a.Before(b) {
		return a
	}
	return b
}
