package transport

import (
	"log"
	"net/http"
	"strings"
)

// ─────────────────────────────────────────────
// OIDC / OAuth2 Handlers (PA as auth broker)
// ─────────────────────────────────────────────

// handleOIDCAuthorize is the OIDC Authorization Endpoint.
// Native endpoint clients redirect the user's browser here to start authentication.
//
// GET /auth/authorize?client_id=<registered-client>&response_type=code&redirect_uri=<registered-callback>&state=xyz&scope=openid
//
// Flow:
//  1. Validates client_id and redirect_uri
//  2. Creates an OIDC authorize session
//  3. Resolves an organization-level external IdP
//  4. Redirects to the external IdP and handles the federation callback
//  5. PA generates an authorization code and redirects to the OIDC client callback
func (s *Server) handleOIDCAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientID := r.URL.Query().Get("client_id")
	responseType := r.URL.Query().Get("response_type")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	scope := r.URL.Query().Get("scope")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
	nonce := r.URL.Query().Get("nonce")
	deviceID := r.URL.Query().Get("device_id")
	hostname := r.URL.Query().Get("hostname")
	acrValues := r.URL.Query().Get("acr_values")

	// Validate required parameters
	if clientID == "" || redirectURI == "" {
		http.Error(w, "Missing required parameters: client_id, redirect_uri", http.StatusBadRequest)
		return
	}

	if responseType != "code" {
		http.Error(w, "Unsupported response_type. Only 'code' is supported.", http.StatusBadRequest)
		return
	}

	// Validate client_id
	client, err := s.pa.Auth.OIDC.ValidateClientID(clientID)
	if err != nil {
		log.Printf("[OIDC] Invalid client_id %s: %v", clientID, err)
		http.Error(w, "Invalid client_id", http.StatusBadRequest)
		return
	}

	// Validate redirect_uri
	if !s.pa.Auth.OIDC.ValidateRedirectURI(client, redirectURI) {
		log.Printf("[OIDC] Invalid redirect_uri %s for client %s", redirectURI, clientID)
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}

	if client.Public || client.RequirePKCE {
		if codeChallenge == "" || codeChallengeMethod != "S256" {
			http.Error(w, "PKCE S256 is required for this client", http.StatusBadRequest)
			return
		}
	}
	if client.RequireDeviceID && strings.TrimSpace(deviceID) == "" {
		http.Error(w, "device_id is required for endpoint authorization", http.StatusBadRequest)
		return
	}

	// Create an OIDC authorize session
	oidcSession, err := s.pa.Auth.OIDC.CreateAuthorizeSession(clientID, redirectURI, state, scope, codeChallenge, codeChallengeMethod, nonce, deviceID, hostname, acrValues)
	if err != nil {
		log.Printf("[OIDC] Failed to create authorize session: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("[OIDC] Authorize request: client=%s redirect=%s state=%s session=%s",
		clientID, redirectURI, state, oidcSession.ID)

	// ── Identity Broker: resolve the correct organization-level IdP via HRD ──
	idpCfg, organization, err := s.resolveIdentityProvider(r, clientID)
	if err != nil {
		log.Printf("[HRD] Identity provider resolution failed: %v", err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if idpCfg != nil {
		s.redirectToExternalIdP(w, r, oidcSession, organization, idpCfg, nonce)
		return
	}

	http.Error(w, "No external identity provider configured for this organization", http.StatusForbidden)
}
