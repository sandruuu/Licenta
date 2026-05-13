package auth

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ──────────────────────────────────────────────────────────────────────
// OIDC Authorization Code Flow — PA acts as an auth broker/session issuer
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

// OIDCManager manages OIDC authorization state on the PA.
type OIDCManager struct {
	mu sync.RWMutex

	// Registered OIDC clients (native endpoint clients)
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

	authorizeSessionTTL time.Duration
	authCodeTTL         time.Duration
	refreshTokenTTL     time.Duration
	cleanupInterval     time.Duration
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

// NewOIDCManager creates a new OIDC manager using durations loaded from PDP config.
func NewOIDCManager(authorizeSessionTTL, authCodeTTL, refreshTokenTTL, cleanupInterval time.Duration) *OIDCManager {
	mgr := &OIDCManager{
		Clients:             make(map[string]*OIDCClient),
		AuthCodes:           make(map[string]*AuthorizationCode),
		PendingAuthorize:    make(map[string]*OIDCAuthorizeSession),
		RefreshTokens:       make(map[string]*RefreshToken),
		FederationSessions:  make(map[string]*FederationSession),
		authorizeSessionTTL: authorizeSessionTTL,
		authCodeTTL:         authCodeTTL,
		refreshTokenTTL:     refreshTokenTTL,
		cleanupInterval:     cleanupInterval,
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
