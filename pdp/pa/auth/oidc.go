package auth

import (
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"pdp/models"
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
//   1. A registered endpoint client opens /auth/authorize.
//   2. PDP shows login or federates to the external IdP.
//   3. PDP generates an auth code and redirects to the registered callback.
//   4. The client exchanges the code for a PDP JWT via POST /auth/token.
// ──────────────────────────────────────────────────────────────────────

// OIDCManager manages OIDC authorization state on the PA.
type OIDCManager struct {
	// Registered OIDC clients are persisted so all PDP replicas validate the
	// same client registry.
	clients OIDCClientStore

	// Pending authorization codes (short-lived, max 60s)
	state RuntimeStateStore

	// Pending OIDC authorize requests — the user has been redirected
	// to the login page but hasn't completed authentication yet.

	// Active refresh tokens (long-lived, rotated on use)

	// Pending federation sessions — user is authenticating at external IdP

	authorizeSessionTTL time.Duration
	authCodeTTL         time.Duration
	refreshTokenTTL     time.Duration
	cleanupInterval     time.Duration
}

type RuntimeStateStore interface {
	SaveEphemeralState(kind, key string, value []byte, expiresAt time.Time) error
	GetEphemeralState(kind, key string) ([]byte, bool)
	TakeEphemeralState(kind, key string) ([]byte, bool, error)
	DeleteEphemeralState(kind, key string) error
	CleanExpiredEphemeralState(now time.Time) int
}

type OIDCClientStore interface {
	SaveOIDCClient(client *models.OIDCClient) error
	GetOIDCClient(clientID string) (*models.OIDCClient, bool)
}

// RefreshToken represents a long-lived token that can be exchanged for
// a new access token. Implements one-time-use rotation: each use revokes
// the old token and issues a new one.
type RefreshToken struct {
	TokenHash string    `json:"token_hash"`
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
type OIDCClient = models.OIDCClient

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
func NewOIDCManager(state RuntimeStateStore, clients OIDCClientStore, authorizeSessionTTL, authCodeTTL, refreshTokenTTL, cleanupInterval time.Duration) *OIDCManager {
	mgr := &OIDCManager{
		clients:             clients,
		state:               state,
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
func (m *OIDCManager) RegisterClient(client *OIDCClient) error {
	if m.clients == nil {
		return fmt.Errorf("OIDC client store is unavailable")
	}
	if client == nil || strings.TrimSpace(client.ClientID) == "" {
		return fmt.Errorf("OIDC client_id is required")
	}
	for _, redirectURI := range client.RedirectURIs {
		if _, ok := parseOIDCRedirectURI(redirectURI); !ok {
			return fmt.Errorf("invalid redirect_uri for client %s: %s", client.ClientID, redirectURI)
		}
	}
	if err := m.clients.SaveOIDCClient(client); err != nil {
		return err
	}
	log.Printf("[OIDC] Client registered: %s (%s)", client.ClientID, client.Name)
	return nil
}

// ValidateClientID checks that a client_id is registered (no secret required)
func (m *OIDCManager) ValidateClientID(clientID string) (*OIDCClient, error) {
	if m.clients == nil {
		return nil, fmt.Errorf("OIDC client store is unavailable")
	}
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	client, ok := m.clients.GetOIDCClient(clientID)
	if !ok {
		return nil, fmt.Errorf("unknown client_id: %s", clientID)
	}
	return client, nil
}

// ValidateRedirectURI checks that the redirect_uri is allowed for the client.
func (m *OIDCManager) ValidateRedirectURI(client *OIDCClient, redirectURI string) bool {
	if len(client.RedirectURIs) == 0 {
		// No redirect URIs configured — reject all (secure default)
		log.Printf("[OIDC] WARN: client %s has no registered redirect URIs; rejecting %s", client.ClientID, redirectURI)
		return false
	}
	for _, allowed := range client.RedirectURIs {
		if oidcRedirectURIsEqual(allowed, redirectURI) {
			return true
		}
	}
	return false
}

func oidcRedirectURIsEqual(allowed, redirectURI string) bool {
	allowedURL, ok := parseOIDCRedirectURI(allowed)
	if !ok {
		return false
	}
	redirectURL, ok := parseOIDCRedirectURI(redirectURI)
	if !ok {
		return false
	}
	return strings.EqualFold(allowedURL.Scheme, redirectURL.Scheme) &&
		strings.EqualFold(allowedURL.Host, redirectURL.Host) &&
		allowedURL.EscapedPath() == redirectURL.EscapedPath() &&
		allowedURL.RawQuery == redirectURL.RawQuery
}

func parseOIDCRedirectURI(raw string) (*url.URL, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.Contains(raw, "*") {
		return nil, false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil {
		return nil, false
	}
	if parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, false
	}
	if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return nil, false
	}
	return parsed, true
}
