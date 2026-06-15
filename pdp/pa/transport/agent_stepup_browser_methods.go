package transport

import (
	"encoding/hex"
	"html"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"pdp/models"
	"pdp/pa"
	paauth "pdp/pa/auth"

	"github.com/go-webauthn/webauthn/webauthn"
)

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
