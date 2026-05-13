package auth

import (
	"crypto/subtle"
	"fmt"
	"log"
	"time"
)

// RefreshAccessToken validates a refresh token and performs one-time-use rotation:
// the old token is revoked and a new refresh token is issued. The caller must
// issue a new access token (JWT) using the returned user identity.
func (m *OIDCManager) RefreshAccessToken(refreshToken, clientID, clientSecret string) (*RefreshToken, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rt, ok := m.RefreshTokens[refreshToken]
	if !ok {
		return nil, "", fmt.Errorf("invalid refresh token")
	}

	// One-time use: if already used, revoke and reject (replay detection)
	if rt.Used {
		delete(m.RefreshTokens, refreshToken)
		log.Printf("[OIDC] SECURITY: refresh token replay detected for user=%s client=%s", rt.Username, rt.ClientID)
		return nil, "", fmt.Errorf("refresh token already used (possible replay)")
	}

	if time.Now().After(rt.ExpiresAt) {
		delete(m.RefreshTokens, refreshToken)
		return nil, "", fmt.Errorf("refresh token expired")
	}

	if rt.ClientID != clientID {
		return nil, "", fmt.Errorf("client_id mismatch")
	}

	// Validate client secret
	client, ok := m.Clients[clientID]
	if !ok {
		return nil, "", fmt.Errorf("unknown client_id: %s", clientID)
	}
	if client.ClientSecret != "" && subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(clientSecret)) != 1 {
		return nil, "", fmt.Errorf("invalid client_secret")
	}

	// Rotate: mark old token as used, issue new one
	rt.Used = true

	newToken, err := generateOIDCCode()
	if err != nil {
		return nil, "", fmt.Errorf("generate new refresh token: %w", err)
	}

	newRT := &RefreshToken{
		Token:     newToken,
		ClientID:  clientID,
		UserID:    rt.UserID,
		Username:  rt.Username,
		Role:      rt.Role,
		DeviceID:  rt.DeviceID,
		MFADone:   rt.MFADone,
		Scope:     rt.Scope,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(m.refreshTokenTTL),
		Used:      false,
	}
	m.RefreshTokens[newToken] = newRT

	log.Printf("[OIDC] Refresh token rotated: user=%s client=%s", rt.Username, clientID)

	return newRT, newToken, nil
}

// cleanupLoop periodically removes expired codes and sessions
func (m *OIDCManager) cleanupLoop() {
	ticker := time.NewTicker(m.cleanupInterval)
	for range ticker.C {
		m.mu.Lock()
		now := time.Now()

		for code, ac := range m.AuthCodes {
			if now.After(ac.ExpiresAt) || ac.Used {
				delete(m.AuthCodes, code)
			}
		}

		for id, sess := range m.PendingAuthorize {
			if now.After(sess.ExpiresAt) {
				delete(m.PendingAuthorize, id)
			}
		}

		for token, rt := range m.RefreshTokens {
			if now.After(rt.ExpiresAt) || rt.Used {
				delete(m.RefreshTokens, token)
			}
		}

		for state, fs := range m.FederationSessions {
			if now.After(fs.ExpiresAt) {
				delete(m.FederationSessions, state)
			}
		}

		m.mu.Unlock()
	}
}
