package transport

import (
	"html"
	"log"
	"net/http"
	"strings"
	"time"

	"pdp/models"
	"pdp/pa/auth"
	paenrollment "pdp/pa/enrollment"
	"pdp/util"
)

func (s *Server) handleBrowserEnroll(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/browser/enroll/"), "/")
	if sessionID == "" {
		http.NotFound(w, r)
		return
	}
	session, ok := s.pa.Enrollment.GetInteractiveSession(sessionID)
	if !ok {
		renderEnrollmentPage(w, "Enrollment unavailable", "The enrollment session was not found or has expired.", "", false)
		return
	}
	if time.Now().UTC().After(session.ExpiresAt) {
		renderEnrollmentPage(w, "Enrollment expired", "Start enrollment again from TrustAgent.", "", false)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.renderBrowserEnrollState(w, session)
	case http.MethodPost:
		s.handleBrowserEnrollDiscovery(w, r, session)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) renderBrowserEnrollState(w http.ResponseWriter, session *paenrollment.InteractiveSession) {
	switch session.Status {
	case paenrollment.InteractiveStatusWaitingForIDPDiscovery:
		renderEnrollmentPage(w, "Enroll device", "Enter your organization email address.", "", true)
	case paenrollment.InteractiveStatusWaitingForUserLogin:
		renderEnrollmentPage(w, "Continue in browser", "Authentication is in progress. Complete login with your identity provider.", "", false)
	case paenrollment.InteractiveStatusReadyForDeviceProof:
		renderEnrollmentPage(w, "Authentication complete", "You can return to TrustAgent.", "", false)
	case paenrollment.InteractiveStatusEnrolled:
		renderEnrollmentPage(w, "Device enrolled", "You can return to TrustAgent.", "", false)
	case paenrollment.InteractiveStatusDenied:
		renderEnrollmentPage(w, "Enrollment denied", "Authentication failed or the enrollment session was denied.", "", false)
	default:
		renderEnrollmentPage(w, "Enrollment pending", "Continue enrollment from TrustAgent.", "", false)
	}
}

func (s *Server) handleBrowserEnrollDiscovery(w http.ResponseWriter, r *http.Request, session *paenrollment.InteractiveSession) {
	if session.Status != paenrollment.InteractiveStatusWaitingForIDPDiscovery {
		s.renderBrowserEnrollState(w, session)
		return
	}
	if err := r.ParseForm(); err != nil {
		renderEnrollmentPage(w, "Enroll device", "Could not read the submitted email address.", "", true)
		return
	}
	email := strings.TrimSpace(r.Form.Get("email"))
	idpCfg, tenant, ok := s.resolveEnrollmentIdentityProvider(email)
	if !ok {
		renderEnrollmentPage(w, "Enroll device", "We could not determine the organization for this email. Check the address or contact your administrator.", email, true)
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
	if _, err := s.pa.Enrollment.BeginInteractiveIDPLogin(session.ID, tenant, idpCfg, pkceVerifier, nonce, state); err != nil {
		log.Printf("[ENROLL] Failed to lock enrollment session to IdP: session=%s err=%v", session.ID, err)
		http.Error(w, "Enrollment session could not be updated", http.StatusConflict)
		return
	}

	fedCfg := &models.FederationConfig{
		Issuer:        idpCfg.Issuer,
		ClientID:      idpCfg.ClientID,
		ClientSecret:  idpCfg.ClientSecret,
		Scopes:        idpCfg.Scopes,
		AutoDiscovery: idpCfg.AutoDiscovery,
		ClaimMapping:  idpCfg.ClaimMapping,
	}
	authURL, err := s.pa.Auth.Federation.GenerateExternalAuthURL(fedCfg, s.federatedCallbackURL(), state, nonce, pkceChallenge)
	if err != nil {
		log.Printf("[ENROLL] Failed to create IdP auth URL: session=%s idp=%s err=%v", session.ID, idpCfg.ID, err)
		http.Error(w, "Identity provider configuration error", http.StatusInternalServerError)
		return
	}
	log.Printf("[ENROLL] Redirecting enrollment session to IdP: session=%s tenant=%s idp=%s", session.ID, tenant.ID, idpCfg.ID)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Server) resolveEnrollmentIdentityProvider(email string) (*models.IdentityProviderConfig, *models.Tenant, bool) {
	domain := extractDomainFromHint(email)
	if domain != "" {
		if idpCfg, ok := s.pa.Store.FindIdentityProviderByDomain(domain); ok && idpCfg.Enabled {
			if tenant, found := s.pa.Store.GetTenant(idpCfg.TenantID); found && tenant.Enabled {
				return idpCfg, tenant, true
			}
		}
		if tenant, ok := s.pa.Store.FindTenantByDomain(domain); ok && tenant.Enabled {
			if idpCfg, resolvedTenant, ok := s.defaultIdentityProviderForTenant(tenant.ID); ok {
				return idpCfg, resolvedTenant, true
			}
		}
	}
	if idpCfg, tenant, ok := s.singleTenantIdentityProvider(); ok {
		return idpCfg, tenant, true
	}
	return nil, nil, false
}

func (s *Server) handleEnrollmentFederatedCallback(w http.ResponseWriter, r *http.Request, code, state string) bool {
	session, ok := s.pa.Enrollment.GetInteractiveSessionByBrowserState(state)
	if !ok {
		return false
	}
	idpCfg, ok := s.pa.Store.GetIdentityProviderConfig(session.IDPProfileID)
	if !ok || !idpCfg.Enabled {
		http.Error(w, "Enrollment identity provider not found", http.StatusBadRequest)
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
		log.Printf("[ENROLL] Enrollment federation code exchange failed: session=%s err=%v", state, err)
		http.Error(w, "Federation code exchange failed", http.StatusBadGateway)
		return true
	}
	claims, err := s.pa.Auth.Federation.ValidateAndMapExternalClaims(fedCfg, tokenResp.IDToken, session.BrowserNonce, claimMapping)
	if err != nil {
		log.Printf("[ENROLL] Enrollment federation claim mapping failed: session=%s err=%v", state, err)
		http.Error(w, "Failed to extract identity from external IdP", http.StatusBadGateway)
		return true
	}

	role := "user"
	if len(idpCfg.GroupRoleMapping) > 0 && len(claims.Groups) > 0 {
		role = auth.MapGroupsToRole(claims.Groups, idpCfg.GroupRoleMapping)
	}
	user, err := s.pa.Auth.Users.FindOrCreateFederatedUser(claims.Subject, idpCfg.Issuer, claims.Username, claims.Email, role, session.AuthRealmID)
	if err != nil {
		log.Printf("[ENROLL] Enrollment federated user provisioning failed: session=%s err=%v", state, err)
		http.Error(w, "User provisioning failed", http.StatusInternalServerError)
		return true
	}
	if _, err := s.pa.Enrollment.CompleteInteractiveIDPLogin(session.ID, claims.Subject, claims.Email, idpCfg.Issuer, user.ID, user.Username); err != nil {
		log.Printf("[ENROLL] Failed to complete enrollment IdP login: session=%s err=%v", session.ID, err)
		http.Error(w, "Enrollment session could not be completed", http.StatusConflict)
		return true
	}
	s.pa.Audit.LogEvent("device_enrollment_authenticated", user.ID, user.Username, r.RemoteAddr, "", "", "User authenticated for TrustAgent device enrollment via "+idpCfg.Issuer, true)
	renderEnrollmentPage(w, "Authentication complete", "You can return to TrustAgent.", "", false)
	return true
}

func renderEnrollmentPage(w http.ResponseWriter, title, message, email string, showForm bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var form string
	if showForm {
		form = `<form method="post"><input name="email" type="email" autocomplete="email" placeholder="user@company.com" value="` + html.EscapeString(email) + `" required autofocus><button type="submit">Continue</button></form>`
	}
	_, _ = w.Write([]byte(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>` + html.EscapeString(title) + `</title><style>body{font-family:Segoe UI,Arial,sans-serif;background:#f6f8fb;color:#172033;margin:0;display:grid;min-height:100vh;place-items:center}.panel{width:min(420px,calc(100vw - 32px));background:white;border:1px solid #d9e0ea;border-radius:8px;padding:28px;box-shadow:0 16px 50px rgba(20,35,60,.12)}h1{font-size:24px;margin:0 0 10px}p{color:#56657a;line-height:1.5}form{display:grid;gap:12px;margin-top:20px}input{height:42px;border:1px solid #b9c3d0;border-radius:6px;padding:0 12px;font-size:15px}button{height:42px;border:0;border-radius:6px;background:#1f6feb;color:white;font-weight:700;cursor:pointer}</style></head><body><main class="panel"><h1>` + html.EscapeString(title) + `</h1><p>` + html.EscapeString(message) + `</p>` + form + `</main></body></html>`))
}
