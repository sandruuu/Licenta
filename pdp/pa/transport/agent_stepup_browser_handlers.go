package transport

import (
	"html"
	"log"
	"net/http"
	"strings"
	"time"

	"pdp/models"
	"pdp/pa"
)

const maxStepUpRequestBody = 1 << 20
const stepUpResourceCompleteMessage = "You can close this tab and try to access the resource again."

type stepUpPageMethod struct {
	ID                   string
	Label                string
	Description          string
	Configured           bool
	Active               bool
	EnrollmentAuthorized bool
	ReauthMode           string
}

func (s *Server) handleBrowserStepUp(w http.ResponseWriter, r *http.Request) {
	setNoStoreHeaders(w)
	challengeID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/browser/step-up/"), "/")
	if challengeID == "" {
		http.NotFound(w, r)
		return
	}
	if s == nil || s.pa == nil || s.pa.StepUps == nil {
		renderEnrollmentPage(w, "Verification unavailable", "Step-up verification is not available.", "", false)
		return
	}
	challenge, ok := s.pa.StepUps.Get(challengeID)
	if !ok {
		renderEnrollmentPage(w, "Verification unavailable", "The verification request was not found or has expired.", "", false)
		return
	}
	if r.Method == http.MethodGet && browserCancelledResult(r) {
		renderEnrollmentPage(w, "Verification cancelled", "You can close this tab and go back to the TRUSTAgent app.", "", false)
		return
	}
	now := time.Now().UTC()
	if stepUpChallengeExpired(challenge, now) && challenge.Status != pa.StepUpStatusCompleted {
		renderStepUpExpiredPage(w)
		return
	}
	switch challenge.Status {
	case pa.StepUpStatusCompleted:
		renderEnrollmentPage(w, "Verification complete", stepUpResourceCompleteMessage, "", false)
		return
	case pa.StepUpStatusDenied:
		if strings.EqualFold(strings.TrimSpace(challenge.Reason), "user_cancelled") {
			renderEnrollmentPage(w, "Verification cancelled", "You can close this tab and go back to the TRUSTAgent app.", "", false)
			return
		}
		renderEnrollmentPage(w, "Verification denied", "The verification request was denied.", "", false)
		return
	}

	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, maxStepUpRequestBody)
		if !s.validateStepUpMutationOrigin(r) {
			http.Error(w, "Invalid request origin", http.StatusForbidden)
			return
		}
		if err := r.ParseForm(); err != nil {
			s.renderStepUpPage(w, r, challenge, "Could not read the submitted verification request.", "")
			return
		}
		if !validateCSRFSubmission(r) {
			s.renderStepUpPage(w, r, challenge, "The verification page expired. Refresh and try again.", "")
			return
		}
		if browserFormCancelled(r) {
			s.pa.StepUps.Deny(challenge.ID, "user_cancelled")
			s.logResourceStepUpEvent("agent_step_up_denied", challenge, stepUpRemoteIP(r), models.DecisionDeny, "Resource step-up cancelled by user", false)
			redirectBrowserCancelled(w, r)
			return
		}
		method := strings.ToLower(strings.TrimSpace(r.Form.Get("method")))
		switch method {
		case "reauth":
			s.handleStepUpReauth(w, r, challenge)
		case "totp":
			s.handleStepUpTOTP(w, r, challenge)
		default:
			s.renderStepUpPage(w, r, challenge, "Choose an MFA method to continue.", method)
		}
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	selectedMethod := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("method")))
	if r.URL.Query().Get("reauth") == "1" {
		if s.redirectStepUpReauthIfNeeded(w, r, challenge, selectedMethod) {
			return
		}
	}
	s.renderStepUpPage(w, r, challenge, "", selectedMethod)
}

func (s *Server) handleStepUpTOTP(w http.ResponseWriter, r *http.Request, challenge *pa.StepUpChallenge) {
	if stepUpChallengeExpired(challenge, time.Now().UTC()) {
		renderStepUpExpiredPage(w)
		return
	}
	if !methodAllowed(challenge.Methods, "totp") {
		s.renderStepUpPage(w, r, challenge, "Authenticator app verification is not allowed for this request.", "totp")
		return
	}
	code := totpCodeFromRequest(r)
	if code == "" {
		s.renderStepUpPage(w, r, challenge, "Enter the code from your authenticator app.", "totp")
		return
	}
	if s == nil || s.pa == nil || s.pa.Auth == nil || s.pa.Auth.Users == nil {
		renderEnrollmentPage(w, "Verification unavailable", "PDP MFA services are not available.", "", false)
		return
	}
	user, ok := s.stepUpUser(challenge)
	if !ok || user == nil || user.Disabled {
		s.renderStepUpPage(w, r, challenge, "The user for this verification request is not available.", "totp")
		return
	}

	if s.userHasTOTPConfigured(user) {
		if err := s.pa.Auth.Users.VerifyMFA(challenge.UserID, code); err != nil {
			log.Printf("[STEP-UP] TOTP verification failed: challenge=%s user=%s err=%v", challenge.ID, challenge.UserID, err)
			if _, retryAllowed := s.pa.StepUps.RecordFailedAttempt(challenge.ID, "invalid Authenticator app code"); !retryAllowed {
				s.logResourceStepUpEvent("agent_step_up_denied", challenge, stepUpRemoteIP(r), models.DecisionDeny, "Resource step-up denied after too many invalid Authenticator app codes", false)
				renderEnrollmentPage(w, "Verification denied", "Too many failed verification attempts. Try accessing the protected resource again.", "", false)
				return
			}
			s.renderStepUpPage(w, r, challenge, "The verification code is invalid, expired, or already used.", "totp")
			return
		}
	} else {
		if !s.hasStepUpEnrollmentAuth(r, challenge, "totp") {
			s.renderStepUpPage(w, r, challenge, "Confirm your primary sign-in before setting up an authenticator app.", "totp")
			return
		}
		secret, ok := s.pa.StepUps.PendingTOTPSecret(challenge.ID)
		if !ok || strings.TrimSpace(secret) == "" {
			s.renderStepUpPage(w, r, challenge, "Authenticator app setup expired. Refresh and try again.", "totp")
			return
		}
		if err := s.pa.Auth.Users.ActivateTOTPSecret(challenge.UserID, secret, code); err != nil {
			log.Printf("[STEP-UP] TOTP enrollment verification failed: challenge=%s user=%s err=%v", challenge.ID, challenge.UserID, err)
			if _, retryAllowed := s.pa.StepUps.RecordFailedAttempt(challenge.ID, "invalid Authenticator app setup code"); !retryAllowed {
				s.logResourceStepUpEvent("agent_step_up_denied", challenge, stepUpRemoteIP(r), models.DecisionDeny, "Resource step-up denied after too many invalid Authenticator app setup codes", false)
				renderEnrollmentPage(w, "Verification denied", "Too many failed verification attempts. Try accessing the protected resource again.", "", false)
				return
			}
			s.renderStepUpPage(w, r, challenge, "The setup code is invalid or expired.", "totp")
			return
		}
		if s.pa.Audit != nil {
			s.pa.Audit.LogEvent("agent_mfa_enrolled", challenge.UserID, challenge.Username, r.RemoteAddr, challenge.ResourceID, models.DecisionAllow, "Authenticator app enrolled during resource step-up", true)
		}
		log.Printf("[STEP-UP] TOTP enrolled during challenge=%s user=%s", challenge.ID, challenge.UserID)
	}

	completed, err := s.pa.StepUps.Complete(challenge.ID, "totp", time.Now().UTC())
	if err != nil {
		log.Printf("[STEP-UP] Completing TOTP challenge failed: challenge=%s err=%v", challenge.ID, err)
		if strings.Contains(strings.ToLower(err.Error()), "expired") {
			renderStepUpExpiredPage(w)
			return
		}
		http.Error(w, "Step-up challenge could not be completed", http.StatusConflict)
		return
	}
	if s.pa.Audit != nil {
		s.pa.Audit.LogEvent("agent_step_up_completed", completed.UserID, completed.Username, stepUpRemoteIP(r), completed.ResourceID, models.DecisionAllow, "Step-up completed via Authenticator app", true)
	}
	log.Printf("[STEP-UP] Completed challenge=%s user=%s resource=%s method=totp expires=%s", completed.ID, completed.UserID, completed.ResourceID, completed.ExpiresAt.Format(time.RFC3339))
	renderEnrollmentPage(w, "Verification complete", stepUpResourceCompleteMessage, "", false)
}

func (s *Server) handleStepUpReauth(w http.ResponseWriter, r *http.Request, challenge *pa.StepUpChallenge) {
	if stepUpChallengeExpired(challenge, time.Now().UTC()) {
		renderStepUpExpiredPage(w)
		return
	}
	targetMethod := strings.ToLower(strings.TrimSpace(r.Form.Get("target_method")))
	if targetMethod == "" || !methodAllowed(challenge.Methods, targetMethod) {
		s.renderStepUpPage(w, r, challenge, "Choose an MFA method to continue.", targetMethod)
		return
	}
	user, ok := s.stepUpUser(challenge)
	if !ok || user == nil || user.Disabled {
		s.renderStepUpPage(w, r, challenge, "The user for this verification request is not available.", targetMethod)
		return
	}
	if s.stepUpMethodConfigured(user, targetMethod) {
		http.Redirect(w, r, stepUpMethodURL(challenge.ID, targetMethod), http.StatusSeeOther)
		return
	}
	if strings.TrimSpace(user.PasswordHash) == "" {
		s.renderStepUpPage(w, r, challenge, "Continue with your identity provider before registering this method.", targetMethod)
		return
	}
	locked, until, err := s.pa.Runtime.IsLockedOut(user.Username)
	if err != nil {
		log.Printf("[STEP-UP] Redis lockout check failed for user=%s: %v", user.Username, err)
		s.renderStepUpPage(w, r, challenge, "Primary sign-in state is temporarily unavailable.", targetMethod)
		return
	}
	if locked {
		if s.pa.Audit != nil {
			s.pa.Audit.LogEvent("agent_mfa_enrollment_reauth", user.ID, user.Username, r.RemoteAddr, challenge.ResourceID, models.DecisionDeny, "Primary re-authentication blocked by account lockout", false)
		}
		s.renderStepUpPage(w, r, challenge, "Primary sign-in is temporarily locked until "+until.Format(time.RFC3339)+".", targetMethod)
		return
	}
	password := r.Form.Get("password")
	authenticated, err := s.pa.Auth.Users.Authenticate(user.Username, password)
	if err != nil || authenticated == nil || authenticated.ID != user.ID {
		_ = s.pa.Runtime.RecordFailedLogin(user.Username, s.appConfig().MaxLoginAttempts, s.appConfig().LockoutDuration)
		if _, retryAllowed := s.pa.StepUps.RecordFailedAttempt(challenge.ID, "primary re-authentication failed"); !retryAllowed {
			s.logResourceStepUpEvent("agent_step_up_denied", challenge, stepUpRemoteIP(r), models.DecisionDeny, "Resource step-up denied after too many failed primary re-authentication attempts", false)
			renderEnrollmentPage(w, "Verification denied", "Too many failed verification attempts. Try accessing the protected resource again.", "", false)
			return
		}
		s.renderStepUpPage(w, r, challenge, "Primary sign-in failed. Check the password and try again.", targetMethod)
		return
	}
	_ = s.pa.Runtime.ResetLoginAttempts(user.Username)
	session, err := s.stepUpAuth.create(r, challenge, targetMethod, time.Now().UTC())
	if err != nil {
		log.Printf("[STEP-UP] Re-auth session creation failed: challenge=%s user=%s err=%v", challenge.ID, user.ID, err)
		s.renderStepUpPage(w, r, challenge, "Could not confirm primary sign-in. Try again.", targetMethod)
		return
	}
	s.setStepUpAuthCookie(w, session)
	if s.pa.Audit != nil {
		s.pa.Audit.LogEvent("agent_mfa_enrollment_reauth", user.ID, user.Username, r.RemoteAddr, challenge.ResourceID, models.DecisionAllow, "Primary re-authentication completed for MFA enrollment", true)
	}
	http.Redirect(w, r, stepUpMethodURL(challenge.ID, targetMethod), http.StatusSeeOther)
}

func (s *Server) logResourceStepUpEvent(eventType string, challenge *pa.StepUpChallenge, sourceIP, decision, details string, success bool) {
	if s == nil || s.pa == nil || s.pa.Audit == nil || challenge == nil {
		return
	}
	s.pa.Audit.LogEvent(eventType, challenge.UserID, challenge.Username, sourceIP, challenge.ResourceID, decision, details, success)
}

func (s *Server) renderStepUpPage(w http.ResponseWriter, r *http.Request, challenge *pa.StepUpChallenge, errorMessage, selectedMethod string) {
	csrfToken := s.ensureCSRFCookie(w, r)
	methods := s.stepUpPageMethods(challenge, selectedMethod, r)
	selectedMethod = activeStepUpMethod(methods)

	var setup *models.MFAEnrollResponse
	if selectedMethod == "totp" {
		if user, ok := s.stepUpUser(challenge); ok && user != nil && !s.userHasTOTPConfigured(user) && s.hasStepUpEnrollmentAuth(r, challenge, "totp") {
			var err error
			setup, err = s.ensureTOTPEnrollment(challenge)
			if err != nil && strings.TrimSpace(errorMessage) == "" {
				errorMessage = "Authenticator app setup could not be started."
			}
		}
	}
	methods = s.stepUpPageMethods(challenge, selectedMethod, r)
	activeMethod := activeStepUpMethod(methods)

	var methodCards strings.Builder
	for _, method := range methods {
		if activeMethod != "" && !method.Active {
			continue
		}
		methodCards.WriteString(s.renderStepUpMethodCard(challenge, method, setup, csrfToken))
	}
	if len(methods) == 0 {
		methodCards.WriteString(`<section class="notice">No PDP MFA method is available for this request. Contact your administrator, then try again.</section>`)
	}
	hasActiveMethod := activeMethod != ""
	pageTitle, pageCopy := stepUpPageHeading(methods)
	var alertContent string
	if strings.TrimSpace(errorMessage) != "" {
		alertContent = `<div class="page-alert stepup-alert" role="alert"><svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg><span>` + html.EscapeString(errorMessage) + `</span></div>`
	}
	messageSlot := ""
	if hasActiveMethod || strings.TrimSpace(alertContent) != "" {
		messageSlot = `<div class="stepup-message-slot">` + alertContent + `<div id="webauthn-status" class="webauthn-status" aria-live="polite"></div></div>`
	}
	pageCopyMarkup := ""
	if strings.TrimSpace(pageCopy) != "" {
		pageCopyMarkup = `<p class="stepup-copy">` + html.EscapeString(pageCopy) + `</p>`
	}
	var actionMarkup string
	if hasActiveMethod {
		actionMarkup = `<a class="button-link secondary stepup-back" href="` + html.EscapeString(stepUpSelectionURL(challenge.ID)) + `">Back</a>`
	} else if len(methods) > 0 {
		actionMarkup = `<div class="stepup-selection-spacer" aria-hidden="true"></div>`
	}
	panelClass := "panel stepup-panel" + stepUpPanelVariantClass(methods)
	expiresAt := ""
	if !challenge.ExpiresAt.IsZero() {
		expiresAt = challenge.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TrustCloud verification</title><style>
` + browserPageStyles + `
.stepup-panel{width:min(400px,100%)}
.stepup-panel.admin-mfa-totp .brand,
.stepup-panel.passkey-create-stepup .brand{
  margin-bottom:20px;
}
.stepup-heading{
  max-width:300px;
  margin:0 auto 16px;
}
.stepup-heading h1{
  margin-bottom:12px;
  font-size:18px;
  line-height:24px;
}
.stepup-heading.selection{
  margin:-4px auto 48px;
}
.stepup-heading.selection h1{
  margin-bottom:0;
}
.stepup-copy{
  margin:0;
  color:var(--color-text-secondary);
  font-size:13px;
  line-height:20px;
  text-align:left;
}
.stepup-panel.admin-mfa-totp .stepup-heading{
  margin-bottom:20px;
}
.stepup-panel.identity-stepup .stepup-heading,
.stepup-panel.passkey-create-stepup .stepup-heading{
  margin-bottom:18px;
}
.stepup-message-slot{
  display:flex;
  align-items:center;
  width:100%;
  max-width:300px;
  height:40px;
  margin:0 auto 12px;
}
.webauthn-status{
  width:100%;
  max-width:300px;
}
.webauthn-status:empty{
  display:none;
}
.stepup-message-slot .page-alert,
.webauthn-status .page-alert{
  margin:0;
}
.stepup-alert{max-width:300px}
.methods{
  display:grid;
  gap:12px;
  width:100%;
  max-width:300px;
  margin:0 auto;
}
.method{
  overflow:visible;
  border:0;
  background:transparent;
}
.method.active{
  box-shadow:none;
}
.method-link{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:12px;
  border:1px solid rgba(44,97,100,.55);
  border-radius:6px;
  background:rgba(44,97,100,.045);
  box-shadow:0 8px 16px rgba(42,42,42,.12);
  min-height:58px;
  padding:12px 14px;
  color:inherit;
  text-decoration:none;
  transition:border-color .15s ease,background-color .15s ease,color .15s ease,box-shadow .15s ease;
}
.method-link:hover{
  color:inherit;
  border-color:var(--color-accent);
  background:rgba(44,97,100,.085);
  box-shadow:0 10px 18px rgba(42,42,42,.14);
}
.method-link:active{
  border-color:var(--color-accent);
  background:rgba(44,97,100,.13);
}
.method-link:focus-visible{
  border-color:var(--color-accent);
  background:rgba(44,97,100,.085);
  box-shadow:0 0 0 4px var(--color-accent-muted),0 8px 16px rgba(42,42,42,.12);
  outline:none;
}
.stepup-expired .method-link,
.stepup-expired .button-link,
.stepup-expired button,
.stepup-expired input,
.stepup-expired select,
.stepup-expired textarea{
  opacity:.55;
  cursor:not-allowed;
}
.method.active .method-link{display:none}
.method-head{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:12px;
  min-width:0;
  flex:1;
}
.method-head h2{
  margin-bottom:0;
  font-size:13px;
  line-height:18px;
}
.method-chevron{
  flex:none;
  color:var(--color-accent);
  font-size:24px;
  font-weight:400;
  line-height:1;
}
.method-body{
  border:0;
  background:transparent;
  padding:0;
}
.mfa-help{
  margin-bottom:18px;
  color:var(--color-text-secondary);
  font-size:13px;
  line-height:20px;
  text-align:left;
}
.mfa-setup{
  margin-bottom:16px;
  color:var(--color-text-secondary);
  font-size:13px;
  line-height:20px;
  text-align:left;
}
.mfa-setup-title{
  position:absolute;
  width:1px;
  height:1px;
  overflow:hidden;
  clip:rect(0,0,0,0);
  white-space:nowrap;
}
.mfa-form{
  display:grid;
  gap:18px;
  width:100%;
  max-width:300px;
  margin:0 auto;
  text-align:left;
}
.otp-field{
  display:block;
}
.otp-label{
  position:absolute;
  width:1px;
  height:1px;
  overflow:hidden;
  clip:rect(0,0,0,0);
  white-space:nowrap;
}
.otp{
  display:grid;
  grid-template-columns:repeat(6,minmax(0,1fr));
  gap:8px;
  margin:-4px;
  padding:4px;
}
.otp input{
  width:100%;
  min-width:0;
  height:44px;
  border-radius:6px;
  padding:0;
  text-align:center;
  font-family:ui-monospace,SFMono-Regular,Consolas,monospace;
  font-size:18px;
  font-weight:600;
}
.qr-code{
  display:block;
  width:176px;
  height:176px;
  margin:0 auto 14px;
  border:1px solid var(--color-border);
  border-radius:6px;
  background:#fff;
  padding:8px;
}
.setup-key{
  height:52px;
  margin-top:12px;
  text-align:left;
}
.setup-key summary{
  display:inline-flex;
  align-items:center;
  gap:4px;
  cursor:pointer;
  color:var(--color-text-secondary);
  font-size:12px;
  font-weight:700;
  list-style:none;
}
.setup-key summary::after{
  content:"";
  display:block;
  width:6px;
  height:6px;
  border-right:1.6px solid currentColor;
  border-bottom:1.6px solid currentColor;
  transform:translateY(-2px) rotate(45deg);
  transition:transform .15s ease;
}
.setup-key[open] summary::after{
  transform:translateY(2px) rotate(225deg);
}
.setup-key summary::-webkit-details-marker{display:none}
.setup-key summary:hover{color:var(--color-text-primary)}
.setup-key code{
  display:block;
  min-height:20px;
  max-height:28px;
  margin-top:8px;
  border:0;
  background:transparent;
  color:var(--color-text-primary);
  padding:0;
  font-size:12px;
  line-height:1.5;
  overflow:hidden;
  overflow-wrap:anywhere;
}
.method-body button,.method-body .button-link{
  display:flex;
  width:100%;
  justify-content:center;
  margin-left:auto;
  margin-right:auto;
  margin-top:6px;
}
.mfa-form button{
  margin-top:6px;
}
.button-link.secondary{
  border-color:var(--color-border);
  background:var(--color-surface-card);
  color:var(--color-text-secondary);
  font-weight:500;
  box-shadow:0 8px 16px rgba(42,42,42,.12);
}
.button-link.secondary:hover{
  background:var(--color-surface-hover);
  color:var(--color-text-primary);
}
.stepup-back{
  margin-top:-4px;
}
.stepup-selection-spacer{
  height:28px;
  margin-top:4px;
}
</style></head><body><main id="stepup-root" class="` + panelClass + `" data-challenge-id="` + html.EscapeString(challenge.ID) + `" data-csrf-token="` + html.EscapeString(csrfToken) + `" data-expires-at="` + html.EscapeString(expiresAt) + `">` + browserBrandMarkup + `<div class="stepup-heading` + stepUpHeadingClass(hasActiveMethod) + `"><h1>` + html.EscapeString(pageTitle) + `</h1>` + pageCopyMarkup + `</div>` + messageSlot + `<div class="methods">` + methodCards.String() + actionMarkup + `</div></main><script src="/browser/step-up/assets/stepup.js" defer></script></body></html>`))
}

func (s *Server) renderStepUpMethodCard(challenge *pa.StepUpChallenge, method stepUpPageMethod, setup *models.MFAEnrollResponse, csrfToken string) string {
	className := "method"
	if method.Active {
		className += " active"
	}

	var card strings.Builder
	card.WriteString(`<section class="` + className + `">`)
	card.WriteString(`<a class="method-link" href="` + html.EscapeString(stepUpMethodURL(challenge.ID, method.ID)) + `">`)
	card.WriteString(`<div class="method-head"><h2>` + html.EscapeString(method.Label) + `</h2></div><span class="method-chevron" aria-hidden="true">&rsaquo;</span></a>`)
	if method.Active {
		card.WriteString(`<div class="method-body">`)
		switch method.ID {
		case "totp":
			card.WriteString(renderTOTPMethodBody(challenge.ID, method, setup, csrfToken))
		case "webauthn":
			card.WriteString(renderWebAuthnMethodBody(challenge.ID, method, csrfToken))
		}
		card.WriteString(`</div>`)
	}
	card.WriteString(`</section>`)
	return card.String()
}

func stepUpPageHeading(methods []stepUpPageMethod) (string, string) {
	for _, method := range methods {
		if !method.Active {
			continue
		}
		switch method.ID {
		case "totp":
			if method.Configured {
				return "Two-factor authentication", "Open the Authenticator App configured for two-factor authentication. Type the security code provided by the application."
			}
			if method.EnrollmentAuthorized {
				return "Set up Authenticator app", "Scan the QR code with your Authenticator app"
			}
			if method.ReauthMode == "password" {
				return "Additional identity verification", "Confirm your identity before setting up an Authenticator app."
			}
			if method.ReauthMode == "federated" {
				return "Additional identity verification", "Confirm your identity before setting up an Authenticator app."
			}
			return "Additional identity verification", "Confirm your identity before setting up an Authenticator app."
		case "webauthn":
			if method.Configured {
				return "Two-factor authentication", "Use the passkey or security key registered."
			}
			if method.EnrollmentAuthorized {
				return "Set up passkey", "Create a passkey. The passkey will also complete this verification request."
			}
			if method.ReauthMode == "password" {
				return "Additional identity verification", "Confirm your identity before setting up a passkey."
			}
			if method.ReauthMode == "federated" {
				return "Additional identity verification", "Confirm your identity before setting up a passkey."
			}
			return "Additional identity verification", "Confirm your identity before setting up a passkey."
		}
	}
	return "Additional security verification", ""
}

func stepUpHeadingClass(hasActiveMethod bool) string {
	if hasActiveMethod {
		return ""
	}
	return " selection"
}

func stepUpUsesAdminMFATOTPStyle(methods []stepUpPageMethod) bool {
	for _, method := range methods {
		if method.Active && method.ID == "totp" && (method.Configured || method.EnrollmentAuthorized) {
			return true
		}
	}
	return false
}

func stepUpPanelVariantClass(methods []stepUpPageMethod) string {
	if stepUpUsesAdminMFATOTPStyle(methods) {
		return " admin-mfa-totp"
	}
	for _, method := range methods {
		if method.Active && method.ID == "webauthn" && !method.Configured && !method.EnrollmentAuthorized {
			return " identity-stepup"
		}
		if method.Active && method.ID == "webauthn" && !method.Configured && method.EnrollmentAuthorized {
			return " passkey-create-stepup"
		}
	}
	return ""
}
