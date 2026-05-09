package idp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ──────────────────────────────────────────────────────────────────────
// OIDC Authorization Code Flow — PDP acts as the Identity Provider
//
// This module manages:
//   - OIDC client registrations (native/public clients and confidential clients)
//   - Authorization codes (short-lived, one-time use)
//   - OIDC authorize requests (pending browser authentication sessions)
//
// Flow:
//   1. Connect-App opens /auth/authorize?client_id=connect-app&...
//   2. PDP shows login or federates to the external IdP
//   3. PDP generates an auth code and redirects to the loopback callback
//   4. Connect-App exchanges the code for a PDP JWT via POST /auth/token
// ──────────────────────────────────────────────────────────────────────

// OIDCManager manages OIDC authorization state on the PDP (IdP)
type OIDCManager struct {
	mu sync.RWMutex

	// Registered OIDC clients (gateways)
	Clients map[string]*OIDCClient

	// Pending authorization codes (short-lived, max 60s)
	AuthCodes map[string]*AuthorizationCode

	// Pending OIDC authorize requests — the user has been redirected
	// to the login page but hasn't completed authentication yet.
	PendingAuthorize map[string]*OIDCAuthorizeSession

	// Active refresh tokens (long-lived, rotated on use)
	RefreshTokens map[string]*RefreshToken

	// Pending federation sessions — user is authenticating at external IdP
	FederationSessions map[string]*FederationSession
}

// RefreshToken represents a long-lived token that can be exchanged for
// a new access token. Implements one-time-use rotation: each use revokes
// the old token and issues a new one.
type RefreshToken struct {
	Token     string    `json:"token"`
	ClientID  string    `json:"client_id"`
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	DeviceID  string    `json:"device_id,omitempty"`
	MFADone   bool      `json:"mfa_done"`
	Scope     string    `json:"scope"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"` // one-time use (rotation)
}

// OIDCClient represents a registered OAuth/OIDC client. Public native clients
// have no ClientSecret and must use PKCE S256.
type OIDCClient struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURIs []string `json:"redirect_uris"` // allowed callback URLs
	Name         string   `json:"name"`
	Public       bool     `json:"public"`
	RequirePKCE  bool     `json:"require_pkce"`
}

const (
	NativeConnectAppClientID = "connect-app"
	NativeAgentClientID      = "ztna-agent"
)

// AuthorizationCode is a short-lived code exchanged for tokens.
type AuthorizationCode struct {
	Code                string    `json:"code"`
	ClientID            string    `json:"client_id"`
	RedirectURI         string    `json:"redirect_uri"` // must match exchange request
	UserID              string    `json:"user_id"`
	Username            string    `json:"username"`
	Role                string    `json:"role"`
	DeviceID            string    `json:"device_id,omitempty"`
	MFADone             bool      `json:"mfa_done"`
	Scope               string    `json:"scope"`
	AuthToken           string    `json:"auth_token"`                      // the full JWT issued after login+MFA
	CodeChallenge       string    `json:"code_challenge,omitempty"`        // PKCE S256 challenge
	CodeChallengeMethod string    `json:"code_challenge_method,omitempty"` // "S256"
	Nonce               string    `json:"nonce,omitempty"`                 // OIDC nonce for replay protection
	CreatedAt           time.Time `json:"created_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	Used                bool      `json:"used"` // one-time use
}

// OIDCAuthorizeSession tracks a pending /auth/authorize request while the
// user is authenticating in the browser. The session ID is passed to the
// login page as a query parameter so the completion handler can link the
// authenticated token back to this OIDC request.
type OIDCAuthorizeSession struct {
	ID                  string    `json:"id"`
	ClientID            string    `json:"client_id"`
	RedirectURI         string    `json:"redirect_uri"`
	State               string    `json:"state"` // opaque state from the gateway
	Scope               string    `json:"scope"`
	ACRValues           string    `json:"acr_values,omitempty"`
	CodeChallenge       string    `json:"code_challenge,omitempty"`        // PKCE
	CodeChallengeMethod string    `json:"code_challenge_method,omitempty"` // "S256"
	Nonce               string    `json:"nonce,omitempty"`                 // OIDC nonce
	DeviceID            string    `json:"device_id,omitempty"`
	Hostname            string    `json:"hostname,omitempty"`
	Status              string    `json:"status"` // "pending", "authenticated"
	AuthToken           string    `json:"auth_token,omitempty"`
	UserID              string    `json:"user_id,omitempty"`
	Username            string    `json:"username,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	ExpiresAt           time.Time `json:"expires_at"`
}

// NewOIDCManager creates a new OIDC manager
func NewOIDCManager() *OIDCManager {
	mgr := &OIDCManager{
		Clients:            make(map[string]*OIDCClient),
		AuthCodes:          make(map[string]*AuthorizationCode),
		PendingAuthorize:   make(map[string]*OIDCAuthorizeSession),
		RefreshTokens:      make(map[string]*RefreshToken),
		FederationSessions: make(map[string]*FederationSession),
	}

	// Start background cleanup
	go mgr.cleanupLoop()

	return mgr
}

// RegisterClient adds or updates an OIDC client registration
func (m *OIDCManager) RegisterClient(client *OIDCClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Clients[client.ClientID] = client
	log.Printf("[OIDC] Client registered: %s (%s)", client.ClientID, client.Name)
}

// RegisterNativeConnectAppClient registers the Connect-App as an OAuth/OIDC
// native public client. It has no shared secret and must use PKCE S256 with a
// loopback redirect URI as recommended by RFC 8252 and RFC 7636.
func (m *OIDCManager) RegisterNativeConnectAppClient() {
	m.registerNativeEndpointClient(NativeConnectAppClientID, "ZTNA Connect-App")
}

// RegisterNativeAgentClient registers the final endpoint agent as an
// OAuth/OIDC native public client. It has no shared secret and must use PKCE
// S256 with a loopback redirect URI.
func (m *OIDCManager) RegisterNativeAgentClient() {
	m.registerNativeEndpointClient(NativeAgentClientID, "ZTNA Agent")
}

func (m *OIDCManager) registerNativeEndpointClient(clientID, name string) {
	m.RegisterClient(&OIDCClient{
		ClientID: clientID,
		RedirectURIs: []string{
			"http://127.0.0.1:*",
			"http://localhost:*",
		},
		Name:        name,
		Public:      true,
		RequirePKCE: true,
	})
}

func IsNativeEndpointClientID(clientID string) bool {
	switch strings.TrimSpace(clientID) {
	case NativeConnectAppClientID, NativeAgentClientID:
		return true
	default:
		return false
	}
}

// ValidateClientID checks that a client_id is registered (no secret required)
func (m *OIDCManager) ValidateClientID(clientID string) (*OIDCClient, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	client, ok := m.Clients[clientID]
	if !ok {
		return nil, fmt.Errorf("unknown client_id: %s", clientID)
	}
	return client, nil
}

// ValidateRedirectURI checks that the redirect_uri is allowed for the client.
// Supports exact match or suffix wildcard (entry ending with '*').
func (m *OIDCManager) ValidateRedirectURI(client *OIDCClient, redirectURI string) bool {
	if len(client.RedirectURIs) == 0 {
		// No redirect URIs configured — reject all (secure default)
		log.Printf("[OIDC] WARN: client %s has no registered redirect URIs; rejecting %s", client.ClientID, redirectURI)
		return false
	}
	for _, allowed := range client.RedirectURIs {
		if allowed == redirectURI {
			return true
		}
		if isNativeLoopbackPattern(allowed) {
			if isLoopbackRedirectMatch(allowed, redirectURI) {
				return true
			}
			continue
		}
		if isLoopbackRedirectMatch(allowed, redirectURI) {
			return true
		}
		// Support prefix wildcard: "https://*/auth/callback" style
		if len(allowed) > 1 && allowed[len(allowed)-1] == '*' {
			prefix := allowed[:len(allowed)-1]
			if len(redirectURI) >= len(prefix) && redirectURI[:len(prefix)] == prefix {
				return true
			}
		}
	}
	return false
}

func isNativeLoopbackPattern(allowed string) bool {
	return allowed == "http://127.0.0.1:*" || allowed == "http://localhost:*"
}

func isLoopbackRedirectMatch(allowed, redirectURI string) bool {
	if !isNativeLoopbackPattern(allowed) {
		return false
	}
	u, err := url.Parse(redirectURI)
	if err != nil || u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	if host != "localhost" && !net.ParseIP(host).IsLoopback() {
		return false
	}
	if u.Port() == "" || u.Path != "/callback" {
		return false
	}
	if allowed == "http://127.0.0.1:*" && host != "127.0.0.1" {
		return false
	}
	if allowed == "http://localhost:*" && host != "localhost" {
		return false
	}
	return true
}

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
		ExpiresAt:           time.Now().Add(5 * time.Minute),
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
		ExpiresAt:           time.Now().Add(60 * time.Second), // 1 minute validity
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
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24h lifetime
		Used:      false,
	}

	log.Printf("[OIDC] Authorization code exchanged: user=%s client=%s (refresh_token issued)", authCode.Username, clientID)

	return authCode, refreshToken, nil
}

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
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Used:      false,
	}
	m.RefreshTokens[newToken] = newRT

	log.Printf("[OIDC] Refresh token rotated: user=%s client=%s", rt.Username, clientID)

	return newRT, newToken, nil
}

// cleanupLoop periodically removes expired codes and sessions
func (m *OIDCManager) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
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

// CreateFederationSession stores a pending external IdP authentication session.
func (m *OIDCManager) CreateFederationSession(sess *FederationSession) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.FederationSessions[sess.State] = sess
	log.Printf("[OIDC] Federation session created: state=%s oidc_session=%s gateway=%s",
		sess.State, sess.OIDCSessionID, sess.GatewayID)
}

// GetFederationSession retrieves and removes a federation session by state (one-time use).
func (m *OIDCManager) GetFederationSession(state string) (*FederationSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.FederationSessions[state]
	if ok {
		delete(m.FederationSessions, state)
	}
	return sess, ok
}

func generateOIDCID(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(b), nil
}

func generateOIDCCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
