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
	now := time.Now().UTC()
	if now.After(session.ExpiresAt) {
		s.pa.Enrollment.ExpireInteractiveSessionIfExpired(session.ID, now)
		renderEnrollmentPage(w, "Enrollment expired", "Start enrollment again from TrustAgent.", "", false)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if browserCancelledResult(r) {
			renderEnrollmentPage(w, "Enrollment cancelled", "You can close this tab and go back to the TRUSTAgent app.", "", false)
			return
		}
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
		renderEnrollmentPage(w, "Enroll device", "Enter your email address.", "", true)
	case paenrollment.InteractiveStatusWaitingForUserLogin:
		idpCfg, ok := s.pa.Store.GetIdentityProviderConfig(session.IDPProfileID)
		if ok && idpCfg != nil && idpCfg.Enabled {
			organization, found := s.pa.Store.GetOrganization(session.AuthRealmID)
			if found && organization != nil && organization.Enabled {
				s.redirectBrowserEnrollToIDP(w, nil, session, organization, idpCfg)
				return
			}
		}
		renderEnrollmentPage(w, "Device enrollment in progress", "Complete the sign-in flow, then return to TRUSTAgent.", "", false)
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
	if browserFormCancelled(r) {
		if _, err := s.pa.Enrollment.DenyInteractiveSession(session.ID, "user_cancelled"); err != nil {
			log.Printf("[ENROLL] Failed to cancel enrollment session: session=%s err=%v", session.ID, err)
		}
		redirectBrowserCancelled(w, r)
		return
	}
	email := strings.TrimSpace(r.Form.Get("email"))
	idpCfg, organization, ok := s.resolveEnrollmentIdentityProvider(email)
	if !ok {
		renderEnrollmentPage(w, "Enroll device", "Email does not match any organization directory.", email, true)
		return
	}
	s.redirectBrowserEnrollToIDP(w, r, session, organization, idpCfg)
}

func (s *Server) redirectBrowserEnrollToIDP(w http.ResponseWriter, r *http.Request, session *paenrollment.InteractiveSession, organization *models.Organization, idpCfg *models.IdentityProviderConfig) {
	if session == nil || organization == nil || idpCfg == nil {
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
	if _, err := s.pa.Enrollment.BeginInteractiveIDPLogin(session.ID, organization, idpCfg, pkceVerifier, nonce, state); err != nil {
		log.Printf("[ENROLL] Failed to lock enrollment session to IdP: session=%s err=%v", session.ID, err)
		http.Error(w, "Enrollment session could not be updated", http.StatusConflict)
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
		log.Printf("[ENROLL] Failed to create IdP auth URL: session=%s idp=%s err=%v", session.ID, idpCfg.ID, err)
		http.Error(w, "Identity provider configuration error", http.StatusInternalServerError)
		return
	}
	log.Printf("[ENROLL] Redirecting enrollment session to IdP: session=%s organization=%s idp=%s", session.ID, organization.ID, idpCfg.ID)
	if r != nil {
		http.Redirect(w, r, authURL, http.StatusFound)
		return
	}
	w.Header().Set("Location", authURL)
	w.WriteHeader(http.StatusFound)
}

func (s *Server) resolveEnrollmentIdentityProvider(email string) (*models.IdentityProviderConfig, *models.Organization, bool) {
	domain := extractDomainFromHint(email)
	if domain != "" {
		if idpCfg, ok := s.pa.Store.FindIdentityProviderByDomain(domain); ok && idpCfg.Enabled {
			if organization, found := s.pa.Store.GetOrganization(idpCfg.OrganizationID); found && organization.Enabled {
				return idpCfg, organization, true
			}
		}
		if organization, ok := s.pa.Store.FindOrganizationByDomain(domain); ok && organization.Enabled {
			if idpCfg, resolvedOrganization, ok := s.defaultIdentityProviderForOrganization(organization.ID); ok {
				return idpCfg, resolvedOrganization, true
			}
		}
		return nil, nil, false
	}
	if idpCfg, organization, ok := s.singleOrganizationIdentityProvider(); ok {
		return idpCfg, organization, true
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
		form = `<form method="post"><div><label for="browser-email">Email</label><input id="browser-email" name="email" type="email" autocomplete="email" placeholder="user@company.com" value="` + html.EscapeString(email) + `" required autofocus></div><div class="form-actions"><button type="submit">Continue</button><button type="submit" name="action" value="cancel" class="secondary" formnovalidate>Cancel</button></div></form>`
	}
	lowerTitle := strings.ToLower(title)
	resultMark := browserResultMarkForTitle(lowerTitle)
	if resultMark == "success" && strings.Contains(message, "TrustAgent") {
		message = "You can close this tab and go back to the TRUSTAgent app."
	}
	messageMarkup := `<p class="page-copy">` + html.EscapeString(message) + `</p>`
	if showForm && strings.TrimSpace(message) != "" && !strings.EqualFold(strings.TrimSpace(message), "Enter your email address.") {
		messageMarkup = `<div class="page-alert" role="alert"><svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg><span>` + html.EscapeString(message) + `</span></div>`
	}
	completionMarkup := ""
	if resultMark == "success" {
		completionMarkup = `<svg class="completion-mark" viewBox="0 0 72 72" aria-hidden="true"><path class="completion-ring" pathLength="1" d="M60.7 32.5A25 25 0 1 1 49.2 14.8"/><path class="completion-check" pathLength="1" d="M20 39l13 13 25-31"/></svg>`
	}
	if resultMark == "failure" {
		completionMarkup = `<svg class="cancel-mark" viewBox="0 0 72 72" aria-hidden="true"><circle class="cancel-ring" pathLength="1" cx="36" cy="36" r="25"/><path class="cancel-cross-first" pathLength="1" d="M26 26l20 20"/><path class="cancel-cross-second" pathLength="1" d="M46 26L26 46"/></svg>`
	}
	_, _ = w.Write([]byte(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>` + html.EscapeString(title) + `</title><style>` + browserPageStyles + `</style></head><body><main class="panel">` + browserBrandMarkup + `<h1>` + html.EscapeString(title) + `</h1>` + messageMarkup + form + completionMarkup + `</main></body></html>`))
}

func browserResultMarkForTitle(lowerTitle string) string {
	for _, term := range []string{"cancelled", "canceled", "denied", "unavailable", "expired", "failed", "failure", "unsuccessful"} {
		if strings.Contains(lowerTitle, term) {
			return "failure"
		}
	}
	for _, term := range []string{"complete", "enrolled", "successful", "succeeded"} {
		if strings.Contains(lowerTitle, term) {
			return "success"
		}
	}
	return ""
}

func browserFormCancelled(r *http.Request) bool {
	if r == nil || r.Form == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(r.Form.Get("action")), "cancel")
}

func browserCancelledResult(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	value := strings.TrimSpace(r.URL.Query().Get("cancelled"))
	return value == "1" || strings.EqualFold(value, "true")
}

func redirectBrowserCancelled(w http.ResponseWriter, r *http.Request) {
	if r == nil || r.URL == nil {
		renderEnrollmentPage(w, "Enrollment cancelled", "You can close this tab and go back to the TRUSTAgent app.", "", false)
		return
	}
	http.Redirect(w, r, r.URL.EscapedPath()+"?cancelled=1", http.StatusSeeOther)
}
