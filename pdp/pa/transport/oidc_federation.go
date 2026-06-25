package transport

import (
	"log"
	"net/http"
	"net/url"
	"time"

	"pdp/models"
	"pdp/pa/auth"
)

// redirectToExternalIdP performs the OIDC Authorization Code flow redirect
// to an external IdP using an organization-level IdentityProviderConfig.
func (s *Server) redirectToExternalIdP(w http.ResponseWriter, r *http.Request, oidcSession *auth.OIDCAuthorizeSession, organization *models.Organization, idpCfg *models.IdentityProviderConfig, nonce string) {
	pkceVerifier, pkceChallenge, err := auth.GeneratePKCE()
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	fedState := oidcSession.ID
	fedNonce := nonce

	fedCfg, err := federationConfigFromIdentityProvider(idpCfg, nil, "")
	if err != nil {
		log.Printf("[FEDERATION] Invalid IdP configuration: idp=%s err=%v", idpCfg.ID, err)
		http.Error(w, "Federation configuration error", http.StatusInternalServerError)
		return
	}

	extAuthURL, err := s.pa.Auth.Federation.GenerateExternalAuthURL(
		fedCfg, s.federatedCallbackURL(), fedState, fedNonce, pkceChallenge,
	)
	if err != nil {
		log.Printf("[FEDERATION] Failed to generate external IdP auth URL: %v", err)
		http.Error(w, "Federation configuration error", http.StatusInternalServerError)
		return
	}

	organizationID := ""
	if organization != nil {
		organizationID = organization.ID
	}
	now := time.Now()

	// Store federation session with organization/IdP context for callback
	fedSession := &auth.FederationSession{
		ID:             oidcSession.ID,
		OIDCSessionID:  oidcSession.ID,
		OrganizationID: organizationID,
		IdPID:          idpCfg.ID,
		Issuer:         idpCfg.Issuer,
		PKCEVerifier:   pkceVerifier,
		Nonce:          fedNonce,
		State:          fedState,
		CreatedAt:      now,
		ExpiresAt:      now.Add(s.appConfig().Runtime.OIDCAuthorizeSessionTTL),
	}
	s.pa.Auth.OIDC.CreateFederationSession(fedSession)

	log.Printf("[FEDERATION] Redirecting to external IdP: organization=%s idp=%s issuer=%s", organizationID, idpCfg.Name, idpCfg.Issuer)
	http.Redirect(w, r, extAuthURL, http.StatusFound)
}

// ──────────────────────────────────────────────────────────────────────
// Federation Callback Helpers
// ──────────────────────────────────────────────────────────────────────

// resolveFederatedConfig determines the issuer, claim mapping, and IdP config
// for the callback from the organization-level IdentityProviderConfig captured in
// the federation session.
func (s *Server) resolveFederatedConfig(fedSession *auth.FederationSession) (authSource string, claimMapping map[string]string, idpCfg *models.IdentityProviderConfig) {
	if fedSession.IdPID != "" {
		if cfg, ok := s.pa.Store.GetIdentityProviderConfig(fedSession.IdPID); ok && cfg.Enabled {
			claimMapping := cfg.ClaimMapping
			if claimMapping == nil {
				claimMapping = map[string]string{}
			}
			return cfg.ID, claimMapping, cfg
		}
	}

	return "", nil, nil
}

// buildFederationConfigForExchange constructs a FederationConfig struct for
// the token exchange call from the organization-level IdP config.
// federatedCallbackURL returns the PDP's federated callback URL based on request host.
func (s *Server) federatedCallbackURL() string {
	return s.appConfig().Public.FederatedCallbackURL
}

// handleFederatedCallback receives the authorization code from the external IdP
// after the user authenticates there. It exchanges the code, maps claims,
// provisions the user, issues a PDP JWT, and completes the OIDC session.
//
// GET /auth/federated/callback?code=xxx&state=oidc_session_id
func (s *Server) handleFederatedCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errParam := r.URL.Query().Get("error")

	if errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		log.Printf("[FEDERATION] External IdP returned error: %s — %s", errParam, errDesc)
		http.Error(w, "External IdP error: "+errParam+": "+errDesc, http.StatusBadRequest)
		return
	}

	if code == "" || state == "" {
		http.Error(w, "Missing code or state parameter", http.StatusBadRequest)
		return
	}
	if s.handleEnrollmentFederatedCallback(w, r, code, state) {
		return
	}
	if s.handleAgentSessionFederatedCallback(w, r, code, state) {
		return
	}
	if s.handleStepUpFederatedCallback(w, r, code, state) {
		return
	}

	// Retrieve the federation session (one-time use)
	fedSession, ok := s.pa.Auth.OIDC.GetFederationSession(state)
	if !ok {
		http.Error(w, "Unknown or expired federation session", http.StatusBadRequest)
		return
	}

	if time.Now().After(fedSession.ExpiresAt) {
		http.Error(w, "Federation session expired", http.StatusBadRequest)
		return
	}

	// Resolve the federation config from the organization-level IdentityProviderConfig.
	authSource, claimMapping, idpCfg := s.resolveFederatedConfig(fedSession)
	if authSource == "" {
		http.Error(w, "Federation configuration not found", http.StatusInternalServerError)
		return
	}

	fedCfg, err := federationConfigFromIdentityProvider(idpCfg, claimMapping, "")
	if err != nil {
		log.Printf("[FEDERATION] Invalid IdP configuration during callback: idp=%s err=%v", authSource, err)
		http.Error(w, "Federation configuration invalid", http.StatusInternalServerError)
		return
	}

	tokenResp, err := s.pa.Auth.Federation.ExchangeExternalCode(
		fedCfg, code,
		s.federatedCallbackURL(),
		fedSession.PKCEVerifier,
	)
	if err != nil {
		log.Printf("[FEDERATION] Code exchange failed: %v", err)
		http.Error(w, "Federation code exchange failed", http.StatusBadGateway)
		return
	}

	// Extract identity from the external id_token
	claims, err := s.pa.Auth.Federation.ValidateAndMapExternalClaims(fedCfg, tokenResp.IDToken, fedSession.Nonce, claimMapping)
	if err != nil {
		log.Printf("[FEDERATION] Claim mapping failed: %v", err)
		http.Error(w, "Failed to extract identity from external IdP", http.StatusBadGateway)
		return
	}

	// Determine role from organization IdP group mapping when present.
	role := "user"
	if idpCfg != nil && len(idpCfg.GroupRoleMapping) > 0 && len(claims.Groups) > 0 {
		role = auth.MapGroupsToRole(claims.Groups, idpCfg.GroupRoleMapping)
		log.Printf("[FEDERATION] Group mapping applied: groups=%v → role=%s", claims.Groups, role)
	}

	user, err := s.pa.Auth.Users.FindOrCreateFederatedUser(
		claims.Subject, authSource, claims.Username, claims.Email, role, fedSession.OrganizationID,
	)
	if err != nil {
		log.Printf("[FEDERATION] User provisioning failed: %v", err)
		http.Error(w, "User provisioning failed", http.StatusInternalServerError)
		return
	}

	oidcSess, ok := s.pa.Auth.OIDC.GetAuthorizeSession(fedSession.OIDCSessionID)
	deviceID := ""
	if ok {
		deviceID = oidcSess.DeviceID
	}

	// Issue PDP JWT with MFADone=false (MFA step-up handled at access time)
	// and bind it to the device asserted by the endpoint OIDC request.
	authToken, err := s.pa.Auth.JWT.GenerateAuthToken(user.ID, user.Username, user.Role, deviceID, fedSession.Nonce, false)
	if err != nil {
		http.Error(w, "Token generation failed", http.StatusInternalServerError)
		return
	}

	// Complete the OIDC authorize session → generate authorization code
	authCode, err := s.pa.Auth.OIDC.CompleteAuthorizeSession(
		fedSession.OIDCSessionID, authToken,
		user.ID, user.Username, user.Role, false,
	)
	if err != nil {
		log.Printf("[FEDERATION] OIDC session completion failed: %v", err)
		http.Error(w, "OIDC session completion failed", http.StatusInternalServerError)
		return
	}

	// Build redirect URL back to the OIDC client callback.
	redirectURL := authCode.RedirectURI + "?code=" + url.QueryEscape(authCode.Code)
	if ok && oidcSess.State != "" {
		redirectURL += "&state=" + url.QueryEscape(oidcSess.State)
	}

	log.Printf("[FEDERATION] User authenticated via external IdP: user=%s source=%s → redirect to OIDC client",
		user.Username, authSource)

	s.pa.Audit.LogEvent("federated_login", user.ID, user.Username,
		r.RemoteAddr, "", "", "Federated auth via "+authSource+" (role="+role+") organization="+fedSession.OrganizationID, true)

	http.Redirect(w, r, redirectURL, http.StatusFound)
}
