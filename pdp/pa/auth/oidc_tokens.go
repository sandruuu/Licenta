package auth

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

// RefreshAccessToken validates a refresh token and performs one-time-use rotation:
// the old token is revoked and a new refresh token is issued. The caller must
// issue a new access token (JWT) using the returned user identity.
func (m *OIDCManager) RefreshAccessToken(refreshToken, clientID, clientSecret string) (*RefreshToken, string, error) {
	rt := &RefreshToken{}
	if ok := loadOIDCState(m.state, oidcRefreshStateKind, refreshToken, rt); !ok {
		return nil, "", fmt.Errorf("invalid refresh token")
	}
	if rt.Token != refreshToken {
		return nil, "", fmt.Errorf("invalid refresh token")
	}

	// One-time use: if already used, revoke and reject (replay detection)
	if rt.Used {
		log.Printf("[OIDC] SECURITY: refresh token replay detected for user=%s client=%s", rt.Username, rt.ClientID)
		return nil, "", fmt.Errorf("refresh token already used (possible replay)")
	}

	if time.Now().After(rt.ExpiresAt) {
		return nil, "", fmt.Errorf("refresh token expired")
	}

	if rt.ClientID != clientID {
		return nil, "", fmt.Errorf("client_id mismatch")
	}

	// Validate client secret
	client, err := m.ValidateClientID(clientID)
	if err != nil {
		return nil, "", err
	}
	if client.ClientSecret != "" && subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(clientSecret)) != 1 {
		return nil, "", fmt.Errorf("invalid client_secret")
	}

	raw, ok, err := m.state.TakeEphemeralState(oidcRefreshStateKind, refreshToken)
	if err != nil {
		return nil, "", fmt.Errorf("consume refresh token: %w", err)
	}
	if !ok {
		return nil, "", fmt.Errorf("refresh token already used (possible replay)")
	}
	consumed := &RefreshToken{}
	if err := json.Unmarshal(raw, consumed); err != nil || consumed.Token != rt.Token {
		return nil, "", fmt.Errorf("invalid refresh token")
	}
	if consumed.Used {
		return nil, "", fmt.Errorf("refresh token already used (possible replay)")
	}

	// Rotate: mark old token as used, issue new one
	rt.Used = true
	usedUntil := rt.ExpiresAt
	if !usedUntil.After(time.Now()) {
		usedUntil = time.Now().Add(m.refreshTokenTTL)
	}
	_ = saveOIDCState(m.state, oidcRefreshStateKind, refreshToken, rt, usedUntil)

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
	if err := saveOIDCState(m.state, oidcRefreshStateKind, newToken, newRT, newRT.ExpiresAt); err != nil {
		return nil, "", err
	}

	log.Printf("[OIDC] Refresh token rotated: user=%s client=%s", rt.Username, clientID)

	return newRT, newToken, nil
}

// cleanupLoop periodically removes expired codes and sessions
func (m *OIDCManager) cleanupLoop() {
	ticker := time.NewTicker(m.cleanupInterval)
	for range ticker.C {
		if m.state != nil {
			m.state.CleanExpiredEphemeralState(time.Now().UTC())
		}
	}
}
