package transport

import (
	"log"
	"net/http"
	"strings"
	"time"

	"pdp/models"
	"pdp/pa"
	paauth "pdp/pa/auth"
	"pdp/util"
)

func (s *Server) redirectStepUpReauthIfNeeded(w http.ResponseWriter, r *http.Request, challenge *pa.StepUpChallenge, selectedMethod string) bool {
	selectedMethod = strings.ToLower(strings.TrimSpace(selectedMethod))
	if selectedMethod == "" || challenge == nil || !methodAllowed(challenge.Methods, selectedMethod) {
		return false
	}
	user, ok := s.stepUpUser(challenge)
	if !ok || user == nil || user.Disabled || s.stepUpMethodConfigured(user, selectedMethod) {
		return false
	}
	if stepUpReauthMode(user) != "federated" {
		return false
	}
	if s.hasStepUpEnrollmentAuth(r, challenge, selectedMethod) {
		return false
	}
	if err := s.redirectStepUpReauthToIDP(w, r, challenge, user, selectedMethod); err != nil {
		log.Printf("[STEP-UP] Federated re-auth redirect failed: challenge=%s user=%s err=%v", challenge.ID, user.ID, err)
		s.renderStepUpPage(w, r, challenge, "Could not start identity provider sign-in for MFA setup.", selectedMethod)
	}
	return true
}

func (s *Server) redirectStepUpReauthToIDP(w http.ResponseWriter, r *http.Request, challenge *pa.StepUpChallenge, user *models.User, targetMethod string) error {
	idpCfg, ok := s.identityProviderForStepUpUser(user)
	if !ok {
		return http.ErrNoLocation
	}
	pkceVerifier, pkceChallenge, err := paauth.GeneratePKCE()
	if err != nil {
		return err
	}
	nonce, err := util.GenerateID("nonce")
	if err != nil {
		return err
	}
	state, err := randomSessionSecret(32)
	if err != nil {
		return err
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
		return err
	}
	s.stepUpAuth.saveFederated(&stepUpFederatedReauthSession{
		State:        state,
		ChallengeID:  challenge.ID,
		UserID:       user.ID,
		TargetMethod: strings.ToLower(strings.TrimSpace(targetMethod)),
		TenantID:     user.TenantID,
		IdPID:        idpCfg.ID,
		PKCEVerifier: pkceVerifier,
		Nonce:        nonce,
		ExpiresAt:    time.Now().UTC().Add(s.appConfig().Runtime.BrowserAuthSessionTTL),
	})
	log.Printf("[STEP-UP] Redirecting MFA enrollment re-auth to IdP: challenge=%s tenant=%s idp=%s", challenge.ID, user.TenantID, idpCfg.ID)
	http.Redirect(w, r, authURL, http.StatusFound)
	return nil
}

func (s *Server) handleStepUpFederatedCallback(w http.ResponseWriter, r *http.Request, code, state string) bool {
	session, ok := s.stepUpAuth.takeFederated(state, time.Now().UTC())
	if !ok {
		return false
	}
	challenge, ok := s.pa.StepUps.Get(session.ChallengeID)
	if !ok || challenge == nil || challenge.UserID != session.UserID {
		http.Error(w, "Step-up verification request expired", http.StatusBadRequest)
		return true
	}
	idpCfg, ok := s.pa.Store.GetIdentityProviderConfig(session.IdPID)
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
		log.Printf("[STEP-UP] Federated re-auth code exchange failed: challenge=%s err=%v", session.ChallengeID, err)
		http.Error(w, "Federation code exchange failed", http.StatusBadGateway)
		return true
	}
	claims, err := s.pa.Auth.Federation.ValidateAndMapExternalClaims(fedCfg, tokenResp.IDToken, session.Nonce, claimMapping)
	if err != nil {
		log.Printf("[STEP-UP] Federated re-auth claim mapping failed: challenge=%s err=%v", session.ChallengeID, err)
		http.Error(w, "Failed to extract identity from external IdP", http.StatusBadGateway)
		return true
	}
	user, ok := s.pa.Store.GetUserByExternalSubjectForTenant(claims.Subject, idpCfg.Issuer, session.TenantID)
	if !ok || user == nil || user.ID != session.UserID || user.Disabled {
		http.Error(w, "Federated identity does not match this step-up request", http.StatusForbidden)
		return true
	}
	authSession, err := s.stepUpAuth.create(r, challenge, session.TargetMethod, time.Now().UTC())
	if err != nil {
		http.Error(w, "Step-up re-authentication could not be completed", http.StatusInternalServerError)
		return true
	}
	s.setStepUpAuthCookie(w, authSession)
	if s.pa.Audit != nil {
		s.pa.Audit.LogEvent("agent_mfa_enrollment_reauth", user.ID, user.Username, r.RemoteAddr, challenge.ResourceID, models.DecisionAllow, "Organization sign-in completed for MFA enrollment", true)
	}
	http.Redirect(w, r, stepUpMethodURL(challenge.ID, session.TargetMethod), http.StatusFound)
	return true
}

func (s *Server) identityProviderForStepUpUser(user *models.User) (*models.IdentityProviderConfig, bool) {
	if s == nil || s.pa == nil || s.pa.Store == nil || user == nil {
		return nil, false
	}
	for _, cfg := range s.pa.Store.ListIdentityProviderConfigsForTenant(user.TenantID) {
		if cfg == nil || !cfg.Enabled {
			continue
		}
		if strings.EqualFold(strings.TrimRight(cfg.Issuer, "/"), strings.TrimRight(user.AuthSource, "/")) {
			return cfg, true
		}
	}
	return nil, false
}
