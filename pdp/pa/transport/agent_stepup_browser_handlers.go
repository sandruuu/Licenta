package transport

import (
	"encoding/hex"
	"encoding/json"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"pdp/models"
	"pdp/pa"
	paauth "pdp/pa/auth"
	"pdp/util"

	"github.com/go-webauthn/webauthn/webauthn"
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
	if !challenge.ExpiresAt.IsZero() && now.After(challenge.ExpiresAt) && challenge.Status != pa.StepUpStatusCompleted {
		renderEnrollmentPage(w, "Verification expired", "Try accessing the protected resource again.", "", false)
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
			if _, retryAllowed := s.pa.StepUps.RecordFailedAttempt(challenge.ID, "invalid TOTP code"); !retryAllowed {
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
			if _, retryAllowed := s.pa.StepUps.RecordFailedAttempt(challenge.ID, "invalid TOTP setup code"); !retryAllowed {
				renderEnrollmentPage(w, "Verification denied", "Too many failed verification attempts. Try accessing the protected resource again.", "", false)
				return
			}
			s.renderStepUpPage(w, r, challenge, "The setup code is invalid or expired.", "totp")
			return
		}
		if s.pa.Audit != nil {
			s.pa.Audit.LogEvent("agent_mfa_enrolled", challenge.UserID, challenge.Username, r.RemoteAddr, challenge.ResourceID, models.DecisionAllow, "TOTP enrolled during resource step-up", true)
		}
		log.Printf("[STEP-UP] TOTP enrolled during challenge=%s user=%s", challenge.ID, challenge.UserID)
	}

	completed, err := s.pa.StepUps.Complete(challenge.ID, "totp", time.Now().UTC())
	if err != nil {
		log.Printf("[STEP-UP] Completing TOTP challenge failed: challenge=%s err=%v", challenge.ID, err)
		http.Error(w, "Step-up challenge could not be completed", http.StatusConflict)
		return
	}
	if s.pa.Audit != nil {
		s.pa.Audit.LogEvent("agent_step_up_completed", completed.UserID, completed.Username, r.RemoteAddr, completed.ResourceID, models.DecisionAllow, "Step-up completed via PDP TOTP", true)
	}
	log.Printf("[STEP-UP] Completed challenge=%s user=%s resource=%s method=totp expires=%s", completed.ID, completed.UserID, completed.ResourceID, completed.ExpiresAt.Format(time.RFC3339))
	renderEnrollmentPage(w, "Verification complete", stepUpResourceCompleteMessage, "", false)
}

func (s *Server) handleStepUpReauth(w http.ResponseWriter, r *http.Request, challenge *pa.StepUpChallenge) {
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
	if locked, until := s.pa.Store.IsLockedOut(user.Username); locked {
		if s.pa.Audit != nil {
			s.pa.Audit.LogEvent("agent_mfa_enrollment_reauth", user.ID, user.Username, r.RemoteAddr, challenge.ResourceID, models.DecisionDeny, "Primary re-authentication blocked by account lockout", false)
		}
		s.renderStepUpPage(w, r, challenge, "Primary sign-in is temporarily locked until "+until.Format(time.RFC3339)+".", targetMethod)
		return
	}
	password := r.Form.Get("password")
	authenticated, err := s.pa.Auth.Users.Authenticate(user.Username, password)
	if err != nil || authenticated == nil || authenticated.ID != user.ID {
		s.pa.Store.RecordFailedLogin(user.Username, s.appConfig().MaxLoginAttempts, s.appConfig().LockoutDuration)
		if _, retryAllowed := s.pa.StepUps.RecordFailedAttempt(challenge.ID, "primary re-authentication failed"); !retryAllowed {
			renderEnrollmentPage(w, "Verification denied", "Too many failed verification attempts. Try accessing the protected resource again.", "", false)
			return
		}
		s.renderStepUpPage(w, r, challenge, "Primary sign-in failed. Check the password and try again.", targetMethod)
		return
	}
	s.pa.Store.ResetLoginAttempts(user.Username)
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
</style></head><body><main id="stepup-root" class="` + panelClass + `" data-challenge-id="` + html.EscapeString(challenge.ID) + `" data-csrf-token="` + html.EscapeString(csrfToken) + `">` + browserBrandMarkup + `<div class="stepup-heading` + stepUpHeadingClass(hasActiveMethod) + `"><h1>` + html.EscapeString(pageTitle) + `</h1>` + pageCopyMarkup + `</div>` + messageSlot + `<div class="methods">` + methodCards.String() + actionMarkup + `</div></main><script src="/browser/step-up/assets/stepup.js" defer></script></body></html>`))
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
				return "Two-factor authentication", "Open the Authenticator App that you used to set up two-factor authentication. Type the security code provided by the application."
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

func renderTOTPMethodBody(challengeID string, method stepUpPageMethod, setup *models.MFAEnrollResponse, csrfToken string) string {
	if method.Configured {
		return `<form class="mfa-form" method="post"><input type="hidden" name="csrf_token" value="` + html.EscapeString(csrfToken) + `"><input type="hidden" name="method" value="totp">` + renderTOTPCodeInputs() + `<button type="submit">Verify</button></form>`
	}
	if !method.EnrollmentAuthorized {
		return renderStepUpReauthBody(challengeID, method.ID, method.ReauthMode, csrfToken)
	}
	var body strings.Builder
	body.WriteString(`<div class="mfa-setup"><p class="mfa-setup-title">Set up authenticator app</p>`)
	if setup != nil {
		if strings.TrimSpace(setup.QRCodeImage) != "" {
			body.WriteString(`<img alt="TOTP QR code" class="qr-code" src="`)
			body.WriteString(html.EscapeString(setup.QRCodeImage))
			body.WriteString(`">`)
		}
		body.WriteString(`<details class="setup-key"><summary>Setup token</summary><code>`)
		body.WriteString(html.EscapeString(setup.Secret))
		body.WriteString(`</code></details>`)
	}
	body.WriteString(`</div>`)
	body.WriteString(`<form class="mfa-form" method="post"><input type="hidden" name="csrf_token" value="` + html.EscapeString(csrfToken) + `"><input type="hidden" name="method" value="totp">`)
	body.WriteString(renderTOTPCodeInputs())
	body.WriteString(`<button type="submit">Verify</button></form>`)
	return body.String()
}

func renderTOTPCodeInputs() string {
	var body strings.Builder
	body.WriteString(`<div class="otp-field"><label class="otp-label" for="stepup-totp-code-0">Security code</label><input type="hidden" name="totp_code" class="otp-value"><div class="otp" data-otp-length="6">`)
	for i := 0; i < 6; i++ {
		index := strconv.Itoa(i)
		label := strconv.Itoa(i + 1)
		body.WriteString(`<input id="stepup-totp-code-`)
		body.WriteString(index)
		body.WriteString(`" class="otp-digit" name="totp_digit_`)
		body.WriteString(index)
		body.WriteString(`" type="text" inputmode="numeric" autocomplete="`)
		if i == 0 {
			body.WriteString(`one-time-code`)
		} else {
			body.WriteString(`off`)
		}
		body.WriteString(`" pattern="[0-9]*" maxlength="6" aria-label="TOTP digit `)
		body.WriteString(label)
		body.WriteString(`" required`)
		if i == 0 {
			body.WriteString(` autofocus`)
		}
		body.WriteString(`>`)
	}
	body.WriteString(`</div></div>`)
	return body.String()
}

func totpCodeFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	code := strings.TrimSpace(r.Form.Get("totp_code"))
	if code != "" {
		return code
	}
	var body strings.Builder
	for i := 0; i < 6; i++ {
		body.WriteString(strings.TrimSpace(r.Form.Get("totp_digit_" + strconv.Itoa(i))))
	}
	return body.String()
}

func renderWebAuthnMethodBody(challengeID string, method stepUpPageMethod, csrfToken string) string {
	if method.Configured {
		return `<button type="button" id="webauthn-verify-button">Use passkey</button>`
	}
	if !method.EnrollmentAuthorized {
		return renderStepUpReauthBody(challengeID, method.ID, method.ReauthMode, csrfToken)
	}
	return `<button type="button" id="webauthn-register-button">Create</button>`
}

func renderStepUpReauthBody(challengeID, targetMethod, mode, csrfToken string) string {
	switch mode {
	case "password":
		buttonText := "Continue"
		if strings.EqualFold(strings.TrimSpace(targetMethod), "webauthn") {
			buttonText = "Verify"
		}
		return `<form class="mfa-form" method="post"><input type="hidden" name="csrf_token" value="` + html.EscapeString(csrfToken) + `"><input type="hidden" name="method" value="reauth"><input type="hidden" name="target_method" value="` + html.EscapeString(targetMethod) + `"><div><label for="stepup-reauth-password">Password</label><input id="stepup-reauth-password" type="password" name="password" autocomplete="current-password" placeholder="Password" required autofocus></div><button type="submit">` + buttonText + `</button></form>`
	case "federated":
		return `<a class="button-link" href="` + html.EscapeString(stepUpMethodReauthURL(challengeID, targetMethod)) + `">Verify</a>`
	default:
		return `<section class="notice">Primary re-authentication is required before registering a new MFA method, but this user has no local password or linked identity provider.</section>`
	}
}

func stepUpCompletionFromWebAuthn(cred *webauthn.Credential) pa.StepUpCompletion {
	completion := pa.StepUpCompletion{
		Method:   "webauthn",
		Strength: models.StepUpStrengthPhishingResistant,
	}
	if cred == nil {
		return completion
	}
	completion.AAGUID = formatAAGUID(cred.Authenticator.AAGUID)
	completion.Attachment = normalizeWebAuthnAttachment(string(cred.Authenticator.Attachment))
	if completion.Attachment == "cross_platform" || credentialHasRoamingTransport(cred) {
		completion.Strength = models.StepUpStrengthHardwareKey
	}
	return completion
}

func normalizeWebAuthnAttachment(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "_")
	switch value {
	case "cross_platform":
		return "cross_platform"
	case "platform":
		return "platform"
	default:
		return value
	}
}

func credentialHasRoamingTransport(cred *webauthn.Credential) bool {
	if cred == nil {
		return false
	}
	for _, transport := range cred.Transport {
		switch strings.ToLower(strings.TrimSpace(string(transport))) {
		case "usb", "nfc", "ble", "hybrid":
			return true
		}
	}
	return false
}

func formatAAGUID(value []byte) string {
	if len(value) != 16 {
		return strings.ToLower(hex.EncodeToString(value))
	}
	encoded := strings.ToLower(hex.EncodeToString(value))
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]
}

func (s *Server) stepUpPageMethods(challenge *pa.StepUpChallenge, selected string, r *http.Request) []stepUpPageMethod {
	user, ok := s.stepUpUser(challenge)
	if !ok || user == nil || user.Disabled {
		return nil
	}
	selected = strings.ToLower(strings.TrimSpace(selected))
	methods := make([]stepUpPageMethod, 0, 2)
	for _, methodID := range s.supportedStepUpMethodIDs(challenge) {
		configured := s.stepUpMethodConfigured(user, methodID)
		method := stepUpPageMethod{
			ID:                   methodID,
			Label:                stepUpMethodLabel(methodID),
			Description:          stepUpMethodDescription(methodID, configured),
			Configured:           configured,
			Active:               selected == methodID,
			EnrollmentAuthorized: configured || s.hasStepUpEnrollmentAuth(r, challenge, methodID),
			ReauthMode:           stepUpReauthMode(user),
		}
		methods = append(methods, method)
	}
	if selected != "" && activeStepUpMethod(methods) == "" {
		for i := range methods {
			methods[i].Active = false
		}
	}
	return methods
}

func (s *Server) supportedStepUpMethodIDs(challenge *pa.StepUpChallenge) []string {
	seen := map[string]struct{}{}
	methods := make([]string, 0, 2)
	for _, method := range challenge.Methods {
		method = strings.ToLower(strings.TrimSpace(method))
		if _, ok := seen[method]; ok {
			continue
		}
		if !stepUpMethodMeetsStrength(method, challenge.MinStrength) {
			continue
		}
		switch method {
		case "totp":
			methods = append(methods, method)
		case "webauthn":
			if s != nil && s.pa != nil && s.pa.Auth != nil && s.pa.Auth.WebAuthn != nil {
				methods = append(methods, method)
			}
		default:
			continue
		}
		seen[method] = struct{}{}
	}
	return methods
}

func stepUpMethodMeetsStrength(method, requiredStrength string) bool {
	required := models.StepUpMinStrength(requiredStrength)
	if required == "" || required == models.StepUpStrengthOTP {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "webauthn":
		return true
	case "totp":
		return false
	default:
		return false
	}
}

func stepUpMethodLabel(method string) string {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "webauthn":
		return "Passkey"
	default:
		return "Authenticator app"
	}
}

func stepUpMethodDescription(method string, configured bool) string {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "webauthn":
		if configured {
			return "Use a passkey or hardware security key already registered in PDP."
		}
		return "Register a passkey or hardware security key for this PDP user."
	default:
		if configured {
			return "Use the authenticator app already configured in PDP."
		}
		return "Set up an authenticator app for this PDP user."
	}
}

func activeStepUpMethod(methods []stepUpPageMethod) string {
	for _, method := range methods {
		if method.Active {
			return method.ID
		}
	}
	return ""
}

func stepUpMethodURL(challengeID, method string) string {
	return "/browser/step-up/" + url.PathEscape(strings.TrimSpace(challengeID)) + "?method=" + url.QueryEscape(strings.TrimSpace(method))
}

func stepUpSelectionURL(challengeID string) string {
	return "/browser/step-up/" + url.PathEscape(strings.TrimSpace(challengeID))
}

func stepUpMethodReauthURL(challengeID, method string) string {
	return stepUpMethodURL(challengeID, method) + "&reauth=1"
}

func (s *Server) ensureTOTPEnrollment(challenge *pa.StepUpChallenge) (*models.MFAEnrollResponse, error) {
	if s == nil || s.pa == nil || s.pa.Auth == nil || s.pa.Auth.Users == nil || s.pa.StepUps == nil || challenge == nil {
		return nil, nil
	}
	secret, err := s.pa.StepUps.EnsurePendingTOTPSecret(challenge.ID, paauth.GenerateTOTPSecret)
	if err != nil {
		return nil, err
	}
	user, ok := s.stepUpUser(challenge)
	if !ok || user == nil {
		return nil, nil
	}
	qrURI := paauth.BuildTOTPURI(secret, s.stepUpTOTPIssuer(), user.Username)
	qrImage, _ := paauth.BuildTOTPQRCodeImage(qrURI)
	return &models.MFAEnrollResponse{
		Secret:      secret,
		QRCodeURL:   qrURI,
		QRCodeImage: qrImage,
		Message:     "Scan the QR code with your authenticator app, then verify with a code to complete enrollment",
	}, nil
}

func (s *Server) stepUpTOTPIssuer() string {
	if s != nil && s.pa != nil && s.pa.Cfg != nil && strings.TrimSpace(s.pa.Cfg.TOTPIssuer) != "" {
		return s.pa.Cfg.TOTPIssuer
	}
	return "TrustCloud"
}

func (s *Server) stepUpUser(challenge *pa.StepUpChallenge) (*models.User, bool) {
	if s == nil || s.pa == nil || challenge == nil {
		return nil, false
	}
	if s.pa.Auth != nil && s.pa.Auth.Users != nil {
		if user, ok := s.pa.Auth.Users.GetUser(challenge.UserID); ok {
			return user, true
		}
	}
	if s.pa.Store != nil {
		return s.pa.Store.GetUser(challenge.UserID)
	}
	return nil, false
}

func (s *Server) userHasTOTPConfigured(user *models.User) bool {
	return user != nil && hasMFAMethod(user.MFAMethods, "totp") && strings.TrimSpace(user.TOTPSecret) != ""
}

func (s *Server) stepUpMethodConfigured(user *models.User, method string) bool {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "totp":
		return s.userHasTOTPConfigured(user)
	case "webauthn":
		return user != nil && hasMFAMethod(user.MFAMethods, "webauthn") && s.hasWebAuthnCredential(user.ID)
	default:
		return false
	}
}

func (s *Server) hasWebAuthnCredential(userID string) bool {
	if s == nil || s.pa == nil || s.pa.Auth == nil || s.pa.Auth.WebAuthn == nil {
		return false
	}
	creds, err := s.loadWebAuthnCredentials(userID)
	return err == nil && len(creds) > 0
}

type stepUpWebAuthnBeginRequest struct {
	ChallengeID string `json:"challenge_id"`
}

func (s *Server) handleStepUpWebAuthnBegin(w http.ResponseWriter, r *http.Request) {
	setNoStoreHeaders(w)
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !s.validateStepUpJSONMutation(w, r) {
		return
	}
	var body stepUpWebAuthnBeginRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxStepUpRequestBody)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	challenge, user, ok := s.pendingStepUpChallengeForMethod(body.ChallengeID, "webauthn", true)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "step-up challenge is not available for WebAuthn"})
		return
	}
	creds, err := s.loadWebAuthnCredentials(user.ID)
	if err != nil || len(creds) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no WebAuthn credentials registered"})
		return
	}
	opts, err := s.pa.Auth.WebAuthn.BeginAuthentication(user, creds, challenge.ID)
	if err != nil {
		log.Printf("[STEP-UP] WebAuthn begin failed: challenge=%s user=%s err=%v", challenge.ID, user.ID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to start WebAuthn verification"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(opts)
}

func (s *Server) handleStepUpWebAuthnFinish(w http.ResponseWriter, r *http.Request) {
	setNoStoreHeaders(w)
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !s.validateStepUpJSONMutation(w, r) {
		return
	}
	challengeID := strings.TrimSpace(r.URL.Query().Get("challenge_id"))
	challenge, user, ok := s.pendingStepUpChallengeForMethod(challengeID, "webauthn", true)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "step-up challenge is not available for WebAuthn"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxStepUpRequestBody)
	creds, err := s.loadWebAuthnCredentials(user.ID)
	if err != nil || len(creds) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no WebAuthn credentials registered"})
		return
	}
	updatedCred, err := s.pa.Auth.WebAuthn.FinishAuthentication(user, creds, challenge.ID, r)
	if err != nil {
		log.Printf("[STEP-UP] WebAuthn finish failed: challenge=%s user=%s err=%v", challenge.ID, user.ID, err)
		if _, retryAllowed := s.pa.StepUps.RecordFailedAttempt(challenge.ID, "WebAuthn verification failed"); !retryAllowed {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many failed verification attempts"})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "WebAuthn verification failed"})
		return
	}
	credJSON, _ := json.Marshal(updatedCred)
	credentialJSON := string(credJSON)
	if s.pa.Auth != nil && s.pa.Auth.Users != nil {
		if protected, err := s.pa.Auth.Users.ProtectMFAValue(credentialJSON); err == nil {
			credentialJSON = protected
		}
	}
	if err := s.pa.Store.UpdateWebAuthnCredentialJSON(hex.EncodeToString(updatedCred.ID), credentialJSON); err != nil {
		log.Printf("[STEP-UP] Failed to update WebAuthn credential: challenge=%s credential=%x err=%v", challenge.ID, updatedCred.ID, err)
	}
	completed, err := s.pa.StepUps.CompleteWithAssurance(challenge.ID, stepUpCompletionFromWebAuthn(updatedCred), time.Now().UTC())
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "step-up challenge could not be completed"})
		return
	}
	if s.pa.Audit != nil {
		s.pa.Audit.LogEvent("agent_step_up_completed", completed.UserID, completed.Username, r.RemoteAddr, completed.ResourceID, models.DecisionAllow, "Step-up completed via PDP WebAuthn", true)
	}
	log.Printf("[STEP-UP] Completed challenge=%s user=%s resource=%s method=webauthn expires=%s", completed.ID, completed.UserID, completed.ResourceID, completed.ExpiresAt.Format(time.RFC3339))
	writeJSON(w, http.StatusOK, map[string]string{"status": "completed"})
}

func (s *Server) handleStepUpWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	setNoStoreHeaders(w)
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !s.validateStepUpJSONMutation(w, r) {
		return
	}
	var body stepUpWebAuthnBeginRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxStepUpRequestBody)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	challenge, user, ok := s.pendingStepUpChallengeForMethod(body.ChallengeID, "webauthn", false)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "step-up challenge is not available for passkey setup"})
		return
	}
	if !s.hasStepUpEnrollmentAuth(r, challenge, "webauthn") {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "primary re-authentication is required before passkey setup"})
		return
	}
	existingCreds, err := s.loadWebAuthnCredentials(user.ID)
	if err != nil {
		log.Printf("[STEP-UP] WebAuthn registration credential load failed: challenge=%s user=%s err=%v", challenge.ID, user.ID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load passkey credentials"})
		return
	}
	opts, err := s.pa.Auth.WebAuthn.BeginRegistration(user, existingCreds, challenge.ID)
	if err != nil {
		log.Printf("[STEP-UP] WebAuthn registration begin failed: challenge=%s user=%s err=%v", challenge.ID, user.ID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to start passkey setup"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(opts)
}

func (s *Server) handleStepUpWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	setNoStoreHeaders(w)
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !s.validateStepUpJSONMutation(w, r) {
		return
	}
	challengeID := strings.TrimSpace(r.URL.Query().Get("challenge_id"))
	challenge, user, ok := s.pendingStepUpChallengeForMethod(challengeID, "webauthn", false)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "step-up challenge is not available for passkey setup"})
		return
	}
	if !s.hasStepUpEnrollmentAuth(r, challenge, "webauthn") {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "primary re-authentication is required before passkey setup"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxStepUpRequestBody)
	existingCreds, err := s.loadWebAuthnCredentials(user.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load passkey credentials"})
		return
	}
	cred, err := s.pa.Auth.WebAuthn.FinishRegistration(user, existingCreds, challenge.ID, r)
	if err != nil {
		log.Printf("[STEP-UP] WebAuthn registration finish failed: challenge=%s user=%s err=%v", challenge.ID, user.ID, err)
		if _, retryAllowed := s.pa.StepUps.RecordFailedAttempt(challenge.ID, "WebAuthn setup failed"); !retryAllowed {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many failed verification attempts"})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passkey setup failed"})
		return
	}
	credJSON, _ := json.Marshal(cred)
	credentialJSON := string(credJSON)
	if s.pa.Auth != nil && s.pa.Auth.Users != nil {
		if protected, err := s.pa.Auth.Users.ProtectMFAValue(credentialJSON); err == nil {
			credentialJSON = protected
		}
	}
	credID, err := util.GenerateID("wc")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save passkey"})
		return
	}
	dbCred := &models.WebAuthnCredential{
		ID:             credID,
		UserID:         user.ID,
		CredentialID:   hex.EncodeToString(cred.ID),
		CredentialJSON: credentialJSON,
		Name:           "Passkey",
		CreatedAt:      time.Now().UTC(),
	}
	if err := s.pa.Store.SaveWebAuthnCredential(dbCred); err != nil {
		log.Printf("[STEP-UP] WebAuthn credential save failed: challenge=%s user=%s err=%v", challenge.ID, user.ID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save passkey"})
		return
	}
	s.pa.Auth.Users.AddMFAMethod(user.ID, "webauthn")
	if s.pa.Audit != nil {
		s.pa.Audit.LogEvent("agent_mfa_enrolled", user.ID, user.Username, r.RemoteAddr, challenge.ResourceID, models.DecisionAllow, "Passkey enrolled during resource step-up", true)
	}
	completed, err := s.pa.StepUps.CompleteWithAssurance(challenge.ID, stepUpCompletionFromWebAuthn(cred), time.Now().UTC())
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "step-up challenge could not be completed"})
		return
	}
	if s.pa.Audit != nil {
		s.pa.Audit.LogEvent("agent_step_up_completed", completed.UserID, completed.Username, r.RemoteAddr, completed.ResourceID, models.DecisionAllow, "Step-up completed via PDP WebAuthn enrollment", true)
	}
	log.Printf("[STEP-UP] WebAuthn enrolled and completed challenge=%s user=%s resource=%s expires=%s", completed.ID, completed.UserID, completed.ResourceID, completed.ExpiresAt.Format(time.RFC3339))
	writeJSON(w, http.StatusOK, map[string]string{"status": "completed"})
}

func (s *Server) validateStepUpJSONMutation(w http.ResponseWriter, r *http.Request) bool {
	if !s.validateStepUpMutationOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid request origin"})
		return false
	}
	if !validateCSRFSubmission(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid CSRF token"})
		return false
	}
	return true
}

func (s *Server) pendingStepUpChallengeForMethod(challengeID, method string, requireConfigured bool) (*pa.StepUpChallenge, *models.User, bool) {
	if s == nil || s.pa == nil || s.pa.StepUps == nil || s.pa.Auth == nil || s.pa.Auth.WebAuthn == nil {
		return nil, nil, false
	}
	challenge, ok := s.pa.StepUps.Get(strings.TrimSpace(challengeID))
	if !ok || challenge == nil {
		return nil, nil, false
	}
	if challenge.Status != pa.StepUpStatusPending && challenge.Status != pa.StepUpStatusAwaiting {
		return nil, nil, false
	}
	if !challenge.ExpiresAt.IsZero() && time.Now().UTC().After(challenge.ExpiresAt) {
		return nil, nil, false
	}
	if !methodAllowed(challenge.Methods, method) {
		return nil, nil, false
	}
	user, ok := s.stepUpUser(challenge)
	if !ok || user == nil || user.Disabled {
		return nil, nil, false
	}
	if requireConfigured && !s.stepUpMethodConfigured(user, method) {
		return nil, nil, false
	}
	return challenge, user, true
}

func methodAllowed(methods []string, expected string) bool {
	expected = strings.ToLower(strings.TrimSpace(expected))
	for _, method := range methods {
		if strings.EqualFold(strings.TrimSpace(method), expected) {
			return true
		}
	}
	return false
}

func hasMFAMethod(methods []string, expected string) bool {
	expected = strings.ToLower(strings.TrimSpace(expected))
	for _, method := range methods {
		if strings.EqualFold(strings.TrimSpace(method), expected) {
			return true
		}
	}
	return false
}

func stepUpReauthMode(user *models.User) string {
	if user == nil {
		return "unavailable"
	}
	if strings.TrimSpace(user.PasswordHash) != "" {
		return "password"
	}
	if strings.TrimSpace(user.ExternalSubject) != "" && strings.TrimSpace(user.AuthSource) != "" {
		return "federated"
	}
	return "unavailable"
}
