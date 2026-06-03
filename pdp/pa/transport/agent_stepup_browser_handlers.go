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
	now := time.Now().UTC()
	if !challenge.ExpiresAt.IsZero() && now.After(challenge.ExpiresAt) && challenge.Status != pa.StepUpStatusCompleted {
		renderEnrollmentPage(w, "Verification expired", "Try accessing the protected resource again.", "", false)
		return
	}
	switch challenge.Status {
	case pa.StepUpStatusCompleted:
		renderEnrollmentPage(w, "Verification complete", "You can return to TrustAgent and retry the resource.", "", false)
		return
	case pa.StepUpStatusDenied:
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
	renderEnrollmentPage(w, "Verification complete", "You can return to TrustAgent and retry the resource.", "", false)
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

	var methodCards strings.Builder
	for _, method := range methods {
		methodCards.WriteString(s.renderStepUpMethodCard(challenge, method, setup, csrfToken))
	}
	if len(methods) == 0 {
		methodCards.WriteString(`<section class="notice">No PDP MFA method is available for this request. Contact your administrator, then try again.</section>`)
	}
	var alert string
	if strings.TrimSpace(errorMessage) != "" {
		alert = `<div class="alert">` + html.EscapeString(errorMessage) + `</div>`
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TrustCloud verification</title><style>
` + browserPageStyles + `
.stepup-panel{width:min(400px,100%)}
.stepup-copy{margin-bottom:14px}
.meta{margin-bottom:18px;color:var(--color-text-muted);font-size:12px}
.methods{
  display:grid;
  gap:12px;
}
.method{
  overflow:hidden;
  border:1px solid var(--color-border);
  border-radius:6px;
  background:var(--color-surface);
}
.method.active{
  border-color:var(--color-accent);
  box-shadow:0 0 0 1px var(--color-accent),0 0 0 4px var(--color-accent-muted);
}
.method-link{
  display:block;
  padding:16px;
  color:inherit;
  text-decoration:none;
}
.method-link:hover{color:inherit;background:var(--color-surface-hover)}
.method-link p{margin-bottom:0}
.method-head{
  display:flex;
  align-items:flex-start;
  justify-content:space-between;
  gap:12px;
}
.badge{
  flex:none;
  border-radius:999px;
  background:var(--color-surface-secondary);
  color:var(--color-text-secondary);
  padding:4px 8px;
  font-size:12px;
  font-weight:700;
  line-height:1;
  white-space:nowrap;
}
.badge.setup{
  background:var(--color-warning-muted);
  color:var(--color-warning);
}
.method-body{
  border-top:1px solid var(--color-border);
  background:var(--color-surface-card);
  padding:16px;
}
.mfa-help{
  margin-bottom:16px;
  color:var(--color-text-secondary);
  font-size:14px;
}
.mfa-setup{
  margin-bottom:16px;
  color:var(--color-text-secondary);
  font-size:14px;
}
.mfa-setup-title{
  margin-bottom:8px;
  color:var(--color-text-primary);
  font-size:14px;
  font-weight:700;
}
.mfa-form{
  gap:12px;
  margin-top:0;
}
.otp-field{
  display:grid;
  gap:8px;
}
.otp-label{
  margin:0;
  color:var(--color-text-primary);
  font-size:14px;
  font-weight:700;
  line-height:1.4;
  text-transform:uppercase;
  letter-spacing:0;
}
.otp{
  display:grid;
  grid-template-columns:repeat(6,minmax(0,1fr));
  gap:8px;
}
.otp input{
  width:100%;
  min-width:0;
  height:44px;
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
  margin:12px auto 14px;
  border:1px solid var(--color-border);
  border-radius:6px;
  background:#fff;
  padding:8px;
}
.setup-key{
  display:grid;
  gap:8px;
  margin-top:12px;
  text-align:left;
}
.setup-key summary{
  cursor:pointer;
  color:var(--color-text-secondary);
  font-size:12px;
  font-weight:700;
  list-style:none;
}
.setup-key summary::-webkit-details-marker{display:none}
.setup-key summary:hover{color:var(--color-text-primary)}
.setup-key code{
  display:block;
  min-height:20px;
  border:0;
  background:transparent;
  color:var(--color-text-primary);
  padding:0;
  font-size:12px;
  line-height:1.5;
  word-break:break-all;
}
.method-body button,.method-body .button-link{
  width:100%;
  justify-content:center;
  margin-top:8px;
}
</style></head><body><main id="stepup-root" class="panel stepup-panel" data-challenge-id="` + html.EscapeString(challenge.ID) + `" data-csrf-token="` + html.EscapeString(csrfToken) + `">` + browserBrandMarkup + `<h1>Additional verification</h1><p class="stepup-copy">PDP requires a step-up check before this resource can be accessed.</p><div class="meta">User: ` + html.EscapeString(challenge.Username) + `</div>` + alert + `<div class="methods">` + methodCards.String() + `</div><div id="webauthn-status" class="status"></div></main><script src="/browser/step-up/assets/stepup.js" defer></script></body></html>`))
}

func (s *Server) renderStepUpMethodCard(challenge *pa.StepUpChallenge, method stepUpPageMethod, setup *models.MFAEnrollResponse, csrfToken string) string {
	badgeClass := "badge"
	badgeText := "Configured"
	if !method.Configured {
		badgeClass += " setup"
		badgeText = "Set up required"
	}
	className := "method"
	if method.Active {
		className += " active"
	}

	var card strings.Builder
	card.WriteString(`<section class="` + className + `">`)
	card.WriteString(`<a class="method-link" href="` + html.EscapeString(stepUpMethodURL(challenge.ID, method.ID)) + `">`)
	card.WriteString(`<div class="method-head"><div><h2>` + html.EscapeString(method.Label) + `</h2><p>` + html.EscapeString(method.Description) + `</p></div>`)
	card.WriteString(`<span class="` + badgeClass + `">` + badgeText + `</span></div></a>`)
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

func renderTOTPMethodBody(challengeID string, method stepUpPageMethod, setup *models.MFAEnrollResponse, csrfToken string) string {
	if method.Configured {
		return `<p class="mfa-help">Enter the current code from your authenticator app.</p><form class="mfa-form" method="post"><input type="hidden" name="csrf_token" value="` + html.EscapeString(csrfToken) + `"><input type="hidden" name="method" value="totp">` + renderTOTPCodeInputs() + `<button type="submit">Verify code</button></form>`
	}
	if !method.EnrollmentAuthorized {
		return renderStepUpReauthBody(challengeID, method.ID, method.ReauthMode, csrfToken)
	}
	var body strings.Builder
	body.WriteString(`<div class="mfa-setup"><p class="mfa-setup-title">Set up authenticator app</p><p>Scan the QR code with your authenticator app, then enter the first code to verify this resource request.</p>`)
	if setup != nil {
		if strings.TrimSpace(setup.QRCodeImage) != "" {
			body.WriteString(`<img alt="TOTP QR code" class="qr-code" src="`)
			body.WriteString(html.EscapeString(setup.QRCodeImage))
			body.WriteString(`">`)
		}
		body.WriteString(`<details class="setup-key"><summary>Can't scan? Show setup key</summary><code>`)
		body.WriteString(html.EscapeString(setup.Secret))
		body.WriteString(`</code></details>`)
	}
	body.WriteString(`</div>`)
	body.WriteString(`<form class="mfa-form" method="post"><input type="hidden" name="csrf_token" value="` + html.EscapeString(csrfToken) + `"><input type="hidden" name="method" value="totp">`)
	body.WriteString(renderTOTPCodeInputs())
	body.WriteString(`<button type="submit">Set up and verify</button></form>`)
	return body.String()
}

func renderTOTPCodeInputs() string {
	var body strings.Builder
	body.WriteString(`<div class="otp-field"><label class="otp-label" for="stepup-totp-code-0">CODE</label><input type="hidden" name="totp_code" class="otp-value"><div class="otp" data-otp-length="6">`)
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
		return `<p>Use the passkey or security key registered in PDP.</p><button type="button" id="webauthn-verify-button">Use passkey</button>`
	}
	if !method.EnrollmentAuthorized {
		return renderStepUpReauthBody(challengeID, method.ID, method.ReauthMode, csrfToken)
	}
	return `<p>Create a passkey for this PDP user. The passkey will also complete this verification request.</p><button type="button" id="webauthn-register-button">Create passkey</button>`
}

func renderStepUpReauthBody(challengeID, targetMethod, mode, csrfToken string) string {
	switch mode {
	case "password":
		return `<p>Confirm your PDP password before registering this MFA method.</p><form method="post"><input type="hidden" name="csrf_token" value="` + html.EscapeString(csrfToken) + `"><input type="hidden" name="method" value="reauth"><input type="hidden" name="target_method" value="` + html.EscapeString(targetMethod) + `"><input type="password" name="password" autocomplete="current-password" placeholder="Password" required autofocus><button type="submit">Continue</button></form>`
	case "federated":
		return `<p>Confirm your identity provider sign-in before registering this MFA method.</p><a class="button-link" href="` + html.EscapeString(stepUpMethodReauthURL(challengeID, targetMethod)) + `">Continue with identity provider</a>`
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
		return "Passkey or security key"
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
