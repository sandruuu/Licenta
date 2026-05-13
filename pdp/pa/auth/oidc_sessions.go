package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log"
	"time"
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

	m.mu.Lock()
	m.PendingAuthorize[id] = session
	m.mu.Unlock()

	log.Printf("[OIDC] Authorize session created: %s (client=%s, state=%s)", id, clientID, state)
	return session, nil
}

// GetAuthorizeSession retrieves a pending OIDC authorize session
func (m *OIDCManager) GetAuthorizeSession(id string) (*OIDCAuthorizeSession, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sess, ok := m.PendingAuthorize[id]
	return sess, ok
}

// CompleteAuthorizeSession marks the session as authenticated and generates
// an authorization code that the gateway can exchange for a token.
func (m *OIDCManager) CompleteAuthorizeSession(sessionID, authToken, userID, username, role string, mfaDone bool) (*AuthorizationCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sess, ok := m.PendingAuthorize[sessionID]
	if !ok {
		return nil, fmt.Errorf("OIDC authorize session not found: %s", sessionID)
	}

	if time.Now().After(sess.ExpiresAt) {
		delete(m.PendingAuthorize, sessionID)
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

	m.AuthCodes[code] = authCode

	// Update session status
	sess.Status = "authenticated"
	sess.AuthToken = authToken
	sess.UserID = userID
	sess.Username = username

	log.Printf("[OIDC] Authorization code generated for session %s: user=%s code=%s...%s",
		sessionID, username, code[:4], code[len(code)-4:])

	return authCode, nil
}

// ExchangeCode exchanges an authorization code for a token.
// The code is single-use and must be used within 60 seconds.
// Returns the auth code and a refresh token string.
func (m *OIDCManager) ExchangeCode(code, clientID, clientSecret, redirectURI, codeVerifier string) (*AuthorizationCode, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	authCode, ok := m.AuthCodes[code]
	if !ok {
		return nil, "", fmt.Errorf("invalid authorization code")
	}

	// Validate: code must not be used
	if authCode.Used {
		// Security: if a code is replayed, invalidate it
		delete(m.AuthCodes, code)
		return nil, "", fmt.Errorf("authorization code already used")
	}

	// Validate: code must not be expired
	if time.Now().After(authCode.ExpiresAt) {
		delete(m.AuthCodes, code)
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
	client, ok := m.Clients[clientID]
	if !ok {
		return nil, "", fmt.Errorf("unknown client_id: %s", clientID)
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

	// Mark as used
	authCode.Used = true

	// Generate a refresh token for the client
	refreshToken, err := generateOIDCCode()
	if err != nil {
		return nil, "", fmt.Errorf("generate refresh token: %w", err)
	}
	m.RefreshTokens[refreshToken] = &RefreshToken{
		Token:     refreshToken,
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

	log.Printf("[OIDC] Authorization code exchanged: user=%s client=%s (refresh_token issued)", authCode.Username, clientID)

	return authCode, refreshToken, nil
}
