package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

const (
	oidcAuthorizeStateKind  = "oidc_authorize"
	oidcAuthCodeStateKind   = "oidc_auth_code"
	oidcRefreshStateKind    = "oidc_refresh"
	oidcFederationStateKind = "oidc_federation"
)

// ──────────────────────────────────────────────────────────────────────
// Authorize session management
// ──────────────────────────────────────────────────────────────────────

// CreateAuthorizeSession creates a pending OIDC authorize session.
// Called when a browser hits /auth/authorize and the login page is shown.
func (m *OIDCManager) CreateAuthorizeSession(clientID, redirectURI, state, scope, codeChallenge, codeChallengeMethod, nonce, deviceID, hostname, acrValues string) (*OIDCAuthorizeSession, error) {
	id, err := generateOIDCID("oidc")
	if err != nil {
		return nil, fmt.Errorf("generate session ID: %w", err)
	}

	session := &OIDCAuthorizeSession{
		ID:                  id,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		State:               state,
		Scope:               scope,
		ACRValues:           acrValues,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Nonce:               nonce,
		DeviceID:            deviceID,
		Hostname:            hostname,
		Status:              "pending",
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(m.authorizeSessionTTL),
	}

	if m.state == nil {
		return nil, fmt.Errorf("OIDC state store is unavailable")
	}
	if err := saveOIDCState(m.state, oidcAuthorizeStateKind, id, session, session.ExpiresAt); err != nil {
		return nil, err
	}

	log.Printf("[OIDC] Authorize session created: %s (client=%s, state=%s)", id, clientID, state)
	return session, nil
}

// GetAuthorizeSession retrieves a pending OIDC authorize session
func (m *OIDCManager) GetAuthorizeSession(id string) (*OIDCAuthorizeSession, bool) {
	var sess OIDCAuthorizeSession
	if ok := loadOIDCState(m.state, oidcAuthorizeStateKind, id, &sess); !ok {
		return nil, false
	}
	if time.Now().After(sess.ExpiresAt) {
		_ = m.state.DeleteEphemeralState(oidcAuthorizeStateKind, id)
		return nil, false
	}
	return &sess, true
}

// CompleteAuthorizeSession marks the session as authenticated and generates
// an authorization code that the gateway can exchange for a token.
func (m *OIDCManager) CompleteAuthorizeSession(sessionID, authToken, userID, username, role string, mfaDone bool) (*AuthorizationCode, error) {
	sess, ok := m.GetAuthorizeSession(sessionID)
	if !ok {
		return nil, fmt.Errorf("OIDC authorize session not found: %s", sessionID)
	}

	if time.Now().After(sess.ExpiresAt) {
		_ = m.state.DeleteEphemeralState(oidcAuthorizeStateKind, sessionID)
		return nil, fmt.Errorf("OIDC authorize session expired")
	}

	// Generate authorization code
	code, err := generateOIDCCode()
	if err != nil {
		return nil, fmt.Errorf("generate auth code: %w", err)
	}

	authCode := &AuthorizationCode{
		Code:                code,
		ClientID:            sess.ClientID,
		RedirectURI:         sess.RedirectURI,
		UserID:              userID,
		Username:            username,
		Role:                role,
		DeviceID:            sess.DeviceID,
		MFADone:             mfaDone,
		Scope:               sess.Scope,
		AuthToken:           authToken,
		CodeChallenge:       sess.CodeChallenge,
		CodeChallengeMethod: sess.CodeChallengeMethod,
		Nonce:               sess.Nonce,
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(m.authCodeTTL),
		Used:                false,
	}

	if err := saveOIDCState(m.state, oidcAuthCodeStateKind, code, authCode, authCode.ExpiresAt); err != nil {
		return nil, err
	}

	// Update session status
	sess.Status = "authenticated"
	sess.AuthToken = authToken
	sess.UserID = userID
	sess.Username = username
	_ = saveOIDCState(m.state, oidcAuthorizeStateKind, sessionID, sess, sess.ExpiresAt)

	log.Printf("[OIDC] Authorization code generated for session %s: user=%s code=%s...%s",
		sessionID, username, code[:4], code[len(code)-4:])

	return authCode, nil
}

// ExchangeCode exchanges an authorization code for a token.
// The code is single-use and must be used within 60 seconds.
// Returns the auth code and a refresh token string.
func (m *OIDCManager) ExchangeCode(code, clientID, clientSecret, redirectURI, codeVerifier string) (*AuthorizationCode, string, error) {
	authCode := &AuthorizationCode{}
	if ok := loadOIDCState(m.state, oidcAuthCodeStateKind, code, authCode); !ok {
		return nil, "", fmt.Errorf("invalid authorization code")
	}
	if authCode.Code != code {
		return nil, "", fmt.Errorf("invalid authorization code")
	}

	// Validate: code must not be used
	if authCode.Used {
		return nil, "", fmt.Errorf("authorization code already used")
	}

	// Validate: code must not be expired
	if time.Now().After(authCode.ExpiresAt) {
		return nil, "", fmt.Errorf("authorization code expired")
	}

	// Validate: client_id must match
	if authCode.ClientID != clientID {
		return nil, "", fmt.Errorf("client_id mismatch")
	}

	// Validate: redirect_uri must match (if present)
	if redirectURI != "" && authCode.RedirectURI != redirectURI {
		return nil, "", fmt.Errorf("redirect_uri mismatch")
	}

	// Validate client secret
	client, err := m.ValidateClientID(clientID)
	if err != nil {
		return nil, "", err
	}
	if client.ClientSecret != "" && subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(clientSecret)) != 1 {
		return nil, "", fmt.Errorf("invalid client_secret")
	}

	// PKCE verification (RFC 7636) — mandatory per OAuth 2.1
	if authCode.CodeChallenge == "" {
		return nil, "", fmt.Errorf("PKCE code_challenge is required (OAuth 2.1)")
	}
	if codeVerifier == "" {
		return nil, "", fmt.Errorf("code_verifier required for PKCE")
	}
	// S256: BASE64URL(SHA256(code_verifier)) must equal code_challenge
	h := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	if subtle.ConstantTimeCompare([]byte(computed), []byte(authCode.CodeChallenge)) != 1 {
		return nil, "", fmt.Errorf("PKCE code_verifier mismatch")
	}

	raw, ok, err := m.state.TakeEphemeralState(oidcAuthCodeStateKind, code)
	if err != nil {
		return nil, "", fmt.Errorf("consume authorization code: %w", err)
	}
	if !ok {
		return nil, "", fmt.Errorf("authorization code already used")
	}
	consumedCode := &AuthorizationCode{}
	if err := json.Unmarshal(raw, consumedCode); err != nil || consumedCode.Code != authCode.Code {
		return nil, "", fmt.Errorf("invalid authorization code")
	}
	if consumedCode.Used {
		return nil, "", fmt.Errorf("authorization code already used")
	}
	consumedCode.Used = true
	replayExpiresAt := consumedCode.ExpiresAt
	if !replayExpiresAt.After(time.Now()) {
		replayExpiresAt = time.Now().Add(m.authCodeTTL)
	}
	_ = saveOIDCState(m.state, oidcAuthCodeStateKind, code, consumedCode, replayExpiresAt)

	// Generate a refresh token for the client
	refreshToken, err := generateOIDCCode()
	if err != nil {
		return nil, "", fmt.Errorf("generate refresh token: %w", err)
	}
	refreshTokenHash := hashOIDCRefreshToken(refreshToken)
	refresh := &RefreshToken{
		TokenHash: refreshTokenHash,
		ClientID:  clientID,
		UserID:    authCode.UserID,
		Username:  authCode.Username,
		Role:      authCode.Role,
		DeviceID:  authCode.DeviceID,
		MFADone:   authCode.MFADone,
		Scope:     authCode.Scope,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(m.refreshTokenTTL),
		Used:      false,
	}
	if err := saveOIDCState(m.state, oidcRefreshStateKind, refreshTokenHash, refresh, refresh.ExpiresAt); err != nil {
		return nil, "", err
	}

	log.Printf("[OIDC] Authorization code exchanged: user=%s client=%s (refresh_token issued)", authCode.Username, clientID)

	return authCode, refreshToken, nil
}

func hashOIDCRefreshToken(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func saveOIDCState(store RuntimeStateStore, kind, key string, value interface{}, expiresAt time.Time) error {
	if store == nil {
		return fmt.Errorf("OIDC state store is unavailable")
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return store.SaveEphemeralState(kind, key, raw, expiresAt)
}

func loadOIDCState(store RuntimeStateStore, kind, key string, value interface{}) bool {
	if store == nil {
		return false
	}
	raw, ok := store.GetEphemeralState(kind, key)
	if !ok {
		return false
	}
	if err := json.Unmarshal(raw, value); err != nil {
		_ = store.DeleteEphemeralState(kind, key)
		return false
	}
	return true
}
