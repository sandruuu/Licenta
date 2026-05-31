package transport

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"pdp/models"
	"pdp/pa/auth"
	"pdp/util"
)

func (s *Server) handleBrowserAgentSession(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/browser/session/"), "/")
	if sessionID == "" {
		http.NotFound(w, r)
		return
	}
	session, ok := s.agentSessions.get(sessionID)
	if !ok {
		renderEnrollmentPage(w, "Authentication unavailable", "The authentication request was not found or has expired.", "", false)
		return
	}
	if time.Now().UTC().After(session.ExpiresAt) {
		renderEnrollmentPage(w, "Authentication expired", "Start login again from TrustAgent.", "", false)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.renderBrowserAgentSessionState(w, r, session)
	case http.MethodPost:
		s.handleBrowserAgentSessionDiscovery(w, r, session)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) renderBrowserAgentSessionState(w http.ResponseWriter, r *http.Request, session *agentSessionTransaction) {
	switch session.Status {
	case agentSessionStatusWaitingForUserLogin:
		if session.IDPProfileID == "" {
			if idpCfg, tenant, ok := s.defaultIdentityProviderForTenant(session.TenantID); ok && tenant != nil && idpCfg != nil {
				s.redirectAgentSessionToIDP(w, r, session, idpCfg)
				return
			}
			renderEnrollmentPage(w, "Sign in", "Enter your organization email address.", "", true)
			return
		}
		if idpCfg, ok := s.pa.Store.GetIdentityProviderConfig(session.IDPProfileID); ok && idpCfg != nil && idpCfg.Enabled {
			s.redirectAgentSessionToIDP(w, r, session, idpCfg)
			return
		}
		renderEnrollmentPage(w, "Continue in browser", "Authentication is in progress. Complete login with your identity provider.", "", false)
	case agentSessionStatusReadyToClaim, agentSessionStatusClaimed:
		renderEnrollmentPage(w, "Authentication complete", "You can return to TrustAgent.", "", false)
	case agentSessionStatusDenied:
		renderEnrollmentPage(w, "Authentication denied", "Authentication failed or access was denied.", "", false)
	default:
		renderEnrollmentPage(w, "Authentication pending", "Continue login from TrustAgent.", "", false)
	}
}

func (s *Server) handleBrowserAgentSessionDiscovery(w http.ResponseWriter, r *http.Request, session *agentSessionTransaction) {
	if session.Status != agentSessionStatusWaitingForUserLogin || session.IDPProfileID != "" {
		s.renderBrowserAgentSessionState(w, r, session)
		return
	}
	if err := r.ParseForm(); err != nil {
		renderEnrollmentPage(w, "Sign in", "Could not read the submitted email address.", "", true)
		return
	}
	email := strings.TrimSpace(r.Form.Get("email"))
	idpCfg, ok := s.resolveAgentSessionIdentityProvider(session.TenantID, email)
	if !ok {
		renderEnrollmentPage(w, "Sign in", "We could not determine the identity provider for this email. Check the address or contact your administrator.", email, true)
		return
	}
	s.redirectAgentSessionToIDP(w, r, session, idpCfg)
}

func (s *Server) resolveAgentSessionIdentityProvider(tenantID, email string) (*models.IdentityProviderConfig, bool) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" || s == nil || s.pa == nil || s.pa.Store == nil {
		return nil, false
	}
	domain := extractDomainFromHint(email)
	if domain != "" {
		for _, cfg := range s.pa.Store.ListIdentityProviderConfigsForTenant(tenantID) {
			if cfg == nil || !cfg.Enabled {
				continue
			}
			for _, candidate := range cfg.Domains {
				if strings.EqualFold(candidate, domain) {
					return cfg, true
				}
			}
		}
	}
	idpCfg, _, ok := s.defaultIdentityProviderForTenant(tenantID)
	return idpCfg, ok
}

func (s *Server) redirectAgentSessionToIDP(w http.ResponseWriter, r *http.Request, session *agentSessionTransaction, idpCfg *models.IdentityProviderConfig) {
	if session == nil || idpCfg == nil {
		http.Error(w, "Identity provider configuration error", http.StatusInternalServerError)
		return
	}
	pkceVerifier, pkceChallenge, err := auth.GeneratePKCE()
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	nonce, err := util.GenerateID("nonce")
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	state, err := randomSessionSecret(32)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if _, err := s.agentSessions.update(session.ID, func(live *agentSessionTransaction) error {
		if live.Status != agentSessionStatusWaitingForUserLogin {
			return fmt.Errorf("authentication request is not waiting for user login")
		}
		if live.IDPProfileID != "" && live.IDPProfileID != idpCfg.ID {
			return fmt.Errorf("identity provider cannot be changed for this authentication request")
		}
		live.IDPProfileID = idpCfg.ID
		live.ExpectedIssuer = strings.TrimSpace(idpCfg.Issuer)
		live.ExpectedClientID = strings.TrimSpace(idpCfg.ClientID)
		live.BrowserState = state
		live.BrowserNonce = nonce
		live.PKCEVerifier = pkceVerifier
		return nil
	}); err != nil {
		http.Error(w, "Authentication request could not be updated", http.StatusConflict)
		return
	}
	fedCfg := &models.FederationConfig{
		Issuer:        idpCfg.Issuer,
		ClientID:      idpCfg.ClientID,
		ClientSecret:  idpCfg.ClientSecret,
		Scopes:        idpCfg.Scopes,
		Prompt:        "login",
		AutoDiscovery: idpCfg.AutoDiscovery,
		ClaimMapping:  idpCfg.ClaimMapping,
	}
	authURL, err := s.pa.Auth.Federation.GenerateExternalAuthURL(fedCfg, s.federatedCallbackURL(), state, nonce, pkceChallenge)
	if err != nil {
		log.Printf("[AGENT-SESSION] Failed to create IdP auth URL: session=%s idp=%s err=%v", session.ID, idpCfg.ID, err)
		http.Error(w, "Identity provider configuration error", http.StatusInternalServerError)
		return
	}
	log.Printf("[AGENT-SESSION] Redirecting session to IdP: session=%s tenant=%s idp=%s", session.ID, session.TenantID, idpCfg.ID)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Server) handleAgentSessionFederatedCallback(w http.ResponseWriter, r *http.Request, code, state string) bool {
	session, ok := s.agentSessions.getByBrowserState(state)
	if !ok {
		return false
	}
	idpCfg, ok := s.pa.Store.GetIdentityProviderConfig(session.IDPProfileID)
	if !ok || idpCfg == nil || !idpCfg.Enabled || !strings.EqualFold(idpCfg.TenantID, session.TenantID) {
		http.Error(w, "Session identity provider not found", http.StatusBadRequest)
		return true
	}
	claimMapping := idpCfg.ClaimMapping
	if claimMapping == nil {
		claimMapping = map[string]string{}
	}
	fedCfg := &models.FederationConfig{
		Issuer:        idpCfg.Issuer,
		ClientID:      idpCfg.ClientID,
		ClientSecret:  idpCfg.ClientSecret,
		Scopes:        idpCfg.Scopes,
		AutoDiscovery: idpCfg.AutoDiscovery,
		ClaimMapping:  claimMapping,
	}
	tokenResp, err := s.pa.Auth.Federation.ExchangeExternalCode(fedCfg, code, s.federatedCallbackURL(), session.PKCEVerifier)
	if err != nil {
		log.Printf("[AGENT-SESSION] Federation code exchange failed: session=%s err=%v", session.ID, err)
		http.Error(w, "Federation code exchange failed", http.StatusBadGateway)
		return true
	}
	claims, err := s.pa.Auth.Federation.ValidateAndMapExternalClaims(fedCfg, tokenResp.IDToken, session.BrowserNonce, claimMapping)
	if err != nil {
		log.Printf("[AGENT-SESSION] Claim mapping failed: session=%s err=%v", session.ID, err)
		http.Error(w, "Failed to extract identity from external IdP", http.StatusBadGateway)
		return true
	}
	role := "user"
	if len(idpCfg.GroupRoleMapping) > 0 && len(claims.Groups) > 0 {
		role = auth.MapGroupsToRole(claims.Groups, idpCfg.GroupRoleMapping)
	}
	user, err := s.pa.Auth.Users.FindOrCreateFederatedUser(claims.Subject, idpCfg.Issuer, claims.Username, claims.Email, role, session.TenantID)
	if err != nil {
		log.Printf("[AGENT-SESSION] Federated user provisioning failed: session=%s err=%v", session.ID, err)
		http.Error(w, "User provisioning failed", http.StatusInternalServerError)
		return true
	}
	if user.Disabled {
		_, _ = s.agentSessions.update(session.ID, func(live *agentSessionTransaction) error {
			live.Status = agentSessionStatusDenied
			live.Reason = "user_disabled"
			return nil
		})
		renderEnrollmentPage(w, "Authentication denied", "Authentication was denied. Contact your administrator.", "", false)
		return true
	}
	if _, err := s.agentSessions.update(session.ID, func(live *agentSessionTransaction) error {
		live.AuthenticatedUserSubject = claims.Subject
		live.AuthenticatedUserEmail = claims.Email
		live.AuthenticatedUserIssuer = idpCfg.Issuer
		live.AuthenticatedUserID = user.ID
		live.AuthenticatedUsername = firstNonEmptyAgentSession(claims.Email, claims.Username, user.Username)
		live.AuthenticatedUserRole = user.Role
		live.Status = agentSessionStatusReadyToClaim
		return nil
	}); err != nil {
		http.Error(w, "Authentication session could not be completed", http.StatusConflict)
		return true
	}
	s.pa.Audit.LogEvent("agent_user_session_authenticated", user.ID, user.Username, r.RemoteAddr, "", "", "User authenticated for TrustAgent session via "+idpCfg.Issuer, true)
	renderEnrollmentPage(w, "Authentication complete", "You can return to TrustAgent.", "", false)
	return true
}

func firstNonEmptyAgentSession(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
