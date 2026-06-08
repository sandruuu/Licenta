package transport

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
)

// handleOIDCCompleteSession is called by the browser login page after the user
// successfully authenticates (login + MFA). It generates an authorization code
// and returns the redirect URL back to the gateway callback.
//
// POST /api/auth/oidc-complete
// Body: { "oidc_session": "oidc_xxx", "auth_token": "jwt..." }
//
// Response: { "redirect_url": "https://gateway/auth/callback?code=xxx&state=yyy" }
func (s *Server) handleOIDCCompleteSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req struct {
		OIDCSession string `json:"oidc_session"`
		AuthToken   string `json:"auth_token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.OIDCSession == "" || req.AuthToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "oidc_session and auth_token are required"})
		return
	}

	// Validate the auth token — allow MFADone=false because MFA enforcement
	// happens at resource access time via the policy engine, not at OIDC completion.
	claims, err := s.pa.Auth.ParseToken(req.AuthToken)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid auth token"})
		return
	}

	// Get user for role info
	user, exists := s.pa.Auth.Users.GetUser(claims.UserID)
	role := claims.Role
	if exists {
		role = user.Role
	}

	oidcSess, ok := s.pa.Auth.OIDC.GetAuthorizeSession(req.OIDCSession)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "OIDC session not found or expired"})
		return
	}

	// Bind the browser-authenticated user token to the device identity carried
	// by the native Connect-App authorize request. This prevents a token minted
	// in an unbound browser-only flow from being replayed through the gateway.
	boundToken, err := s.pa.Auth.JWT.GenerateAuthToken(
		claims.UserID, claims.Username, role,
		oidcSess.DeviceID, oidcSess.Nonce, claims.MFADone,
	)
	if err != nil {
		log.Printf("[OIDC] Failed to issue device-bound token: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token generation failed"})
		return
	}

	// Generate authorization code and complete the OIDC session
	authCode, err := s.pa.Auth.OIDC.CompleteAuthorizeSession(
		req.OIDCSession, boundToken,
		claims.UserID, claims.Username, role, claims.MFADone,
	)
	if err != nil {
		log.Printf("[OIDC] Complete session failed: %v", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "OIDC session completion failed"})
		return
	}

	// Build redirect URL back to the OIDC client callback.
	redirectURL := authCode.RedirectURI + "?code=" + url.QueryEscape(authCode.Code)
	if ok && oidcSess.State != "" {
		redirectURL += "&state=" + url.QueryEscape(oidcSess.State)
	}

	log.Printf("[OIDC] Authorization code issued: user=%s → redirect to %s",
		claims.Username, authCode.RedirectURI)

	writeJSON(w, http.StatusOK, map[string]string{
		"redirect_url": redirectURL,
	})
}
