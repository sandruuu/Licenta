package transport

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"pdp/mfa"
	"pdp/models"
	"pdp/pa"
	"pdp/pa/auth"

	"golang.org/x/crypto/bcrypt"
)

func TestBrowserStepUpOffersTOTPSetupForUserWithoutMFA(t *testing.T) {
	server, dataStore := newDeviceAPITestServer(t)
	challenge := newStepUpBrowserChallenge(t, server, &models.User{
		ID:           "user-stepup",
		Username:     "alice@example.test",
		Email:        "alice@example.test",
		PasswordHash: testPasswordHash(t, "secret"),
		Role:         "user",
		TenantID:     transportTestTenantID,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}, []string{"totp", "webauthn"})

	req := httptest.NewRequest(http.MethodGet, "/browser/step-up/"+challenge.ID+"?method=totp", nil)
	rr := httptest.NewRecorder()
	server.handleBrowserStepUp(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{
		"Additional identity verification",
		"Confirm your identity before setting up an Authenticator app.",
		"Back",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("step-up page missing %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{
		"Additional verification",
		"Confirm your PDP password before setting up an authenticator app.",
		"Confirm your identity provider sign-in before setting up an authenticator app.",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("step-up page should not contain %q: %s", forbidden, body)
		}
	}
	if strings.Contains(body, "Set up required") || strings.Contains(body, "Configured") {
		t.Fatalf("step-up page should not expose MFA configuration status: %s", body)
	}
	csrf := csrfCookie(t, rr)
	authCookie := completeStepUpReauth(t, server, challenge, csrf, "secret")

	req = httptest.NewRequest(http.MethodGet, "/browser/step-up/"+challenge.ID+"?method=totp", nil)
	req.AddCookie(csrf)
	req.AddCookie(authCookie)
	rr = httptest.NewRecorder()
	server.handleBrowserStepUp(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", rr.Code, rr.Body.String())
	}
	body = rr.Body.String()
	for _, want := range []string{
		`class="panel stepup-panel admin-mfa-totp"`,
		"Set up Authenticator app",
		"Scan the QR code with your Authenticator app",
		`class="stepup-message-slot"`,
		`width:176px`,
		`height:176px`,
		"Setup token",
		`.setup-key{`,
		`height:52px`,
		`.setup-key summary::after`,
		`height:44px`,
		"Verify",
		"Back",
		`class="otp-digit"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("authorized setup page missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "Open setup link") {
		t.Fatalf("authorized setup page should not expose the setup link: %s", body)
	}
	for _, forbidden := range []string{
		"Set up Authenticator App",
		"Scan the QR code with your Authenticator App",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("authorized setup page should not contain %q: %s", forbidden, body)
		}
	}
	user, ok := dataStore.GetUser("user-stepup")
	if !ok || strings.TrimSpace(user.TOTPSecret) != "" {
		t.Fatalf("pending TOTP secret should not be stored on user: user=%+v ok=%v", user, ok)
	}
	if secret, ok := server.pa.StepUps.PendingTOTPSecret(challenge.ID); !ok || strings.TrimSpace(secret) == "" {
		t.Fatalf("TOTP setup did not create pending challenge secret")
	}
	if hasMFAMethod(user.MFAMethods, "totp") {
		t.Fatalf("TOTP should not be marked configured before code activation: %+v", user.MFAMethods)
	}
}

func TestBrowserStepUpSelectionMatchesAdminMFAStyle(t *testing.T) {
	server, _ := newDeviceAPITestServer(t)
	server.pa.Cfg.WebAuthnRPID = "localhost"
	server.pa.Cfg.WebAuthnRPName = "TrustCloud"
	server.pa.Cfg.WebAuthnRPOrigins = "https://localhost:8443"
	server.pa.Auth.WebAuthn = mfa.NewWebAuthnProvider(server.pa.Cfg)
	challenge := newStepUpBrowserChallenge(t, server, &models.User{
		ID:           "user-stepup",
		Username:     "alice@example.test",
		Email:        "alice@example.test",
		PasswordHash: testPasswordHash(t, "secret"),
		Role:         "user",
		TenantID:     transportTestTenantID,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}, []string{"totp", "webauthn"})

	req := httptest.NewRequest(http.MethodGet, "/browser/step-up/"+challenge.ID, nil)
	rr := httptest.NewRecorder()
	server.handleBrowserStepUp(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{
		"Additional security verification",
		"Authenticator app",
		"Passkey",
		`class="method-chevron"`,
		`class="stepup-selection-spacer"`,
		`rgba(44,97,100,.045)`,
		`rgba(44,97,100,.085)`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("selection page missing %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{
		"PDP requires a step-up check",
		"User: alice@example.test",
		"Configured",
		"Set up required",
		"SELECT AN OPTION",
		"Passkey or security key",
		"Use the authenticator app already configured in PDP.",
		"Register a passkey or hardware security key for this PDP user.",
		"Cancel",
		`name="action" value="cancel"`,
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("selection page should not contain %q: %s", forbidden, body)
		}
	}

	req = httptest.NewRequest(http.MethodGet, "/browser/step-up/"+challenge.ID+"?method=totp", nil)
	rr = httptest.NewRecorder()
	server.handleBrowserStepUp(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", rr.Code, rr.Body.String())
	}
	body = rr.Body.String()
	for _, want := range []string{"Back", `href="/browser/step-up/` + challenge.ID + `"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("active method page missing %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{`?method=webauthn`, `<h2>Passkey</h2>`, "Cancel"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("active method page should not contain %q: %s", forbidden, body)
		}
	}
}

func TestBrowserStepUpConfiguredTOTPMatchesAdminMFALayout(t *testing.T) {
	server, _ := newDeviceAPITestServer(t)
	server.pa.Cfg.WebAuthnRPID = "localhost"
	server.pa.Cfg.WebAuthnRPName = "TrustCloud"
	server.pa.Cfg.WebAuthnRPOrigins = "https://localhost:8443"
	server.pa.Auth.WebAuthn = mfa.NewWebAuthnProvider(server.pa.Cfg)
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("generate TOTP secret: %v", err)
	}
	challenge := newStepUpBrowserChallenge(t, server, &models.User{
		ID:           "user-stepup",
		Username:     "alice@example.test",
		Email:        "alice@example.test",
		PasswordHash: testPasswordHash(t, "secret"),
		TOTPSecret:   secret,
		MFAMethods:   []string{"totp"},
		Role:         "user",
		TenantID:     transportTestTenantID,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}, []string{"totp", "webauthn"})

	req := httptest.NewRequest(http.MethodGet, "/browser/step-up/"+challenge.ID+"?method=totp", nil)
	rr := httptest.NewRecorder()
	server.handleBrowserStepUp(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{
		`class="panel stepup-panel admin-mfa-totp"`,
		"Two-factor authentication",
		"Open the Authenticator App",
		`class="stepup-message-slot"`,
		`height:44px`,
		`max-width:300px`,
		"Verify",
		"Back",
		`href="/browser/step-up/` + challenge.ID + `"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("configured TOTP page missing %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{`height:66px`, `max-width:330px`, `<h2>Passkey</h2>`, "Cancel"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("configured TOTP page should not contain %q: %s", forbidden, body)
		}
	}
}

func TestBrowserStepUpConfiguredPasskeyCopy(t *testing.T) {
	title, subtitle := stepUpPageHeading([]stepUpPageMethod{{
		ID:         "webauthn",
		Active:     true,
		Configured: true,
	}})

	if title != "Two-factor authentication" {
		t.Fatalf("title = %q, want %q", title, "Two-factor authentication")
	}
	if subtitle != "Use the passkey or security key registered." {
		t.Fatalf("subtitle = %q, want %q", subtitle, "Use the passkey or security key registered.")
	}
	if strings.Contains(subtitle, "PDP") {
		t.Fatalf("subtitle should not mention PDP: %q", subtitle)
	}
}

func TestBrowserStepUpPasskeySetupUsesIdentityVerificationCopy(t *testing.T) {
	server, _ := newDeviceAPITestServer(t)
	server.pa.Cfg.WebAuthnRPID = "localhost"
	server.pa.Cfg.WebAuthnRPName = "TrustCloud"
	server.pa.Cfg.WebAuthnRPOrigins = "https://localhost:8443"
	server.pa.Auth.WebAuthn = mfa.NewWebAuthnProvider(server.pa.Cfg)
	challenge := newStepUpBrowserChallenge(t, server, &models.User{
		ID:              "user-stepup",
		Username:        "alice@example.test",
		Email:           "alice@example.test",
		ExternalSubject: "alice-idp-subject",
		AuthSource:      "https://idp.example.test",
		Role:            "user",
		TenantID:        transportTestTenantID,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}, []string{"webauthn"})

	req := httptest.NewRequest(http.MethodGet, "/browser/step-up/"+challenge.ID+"?method=webauthn", nil)
	rr := httptest.NewRecorder()
	server.handleBrowserStepUp(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{
		`class="panel stepup-panel identity-stepup"`,
		"Additional identity verification",
		"Confirm your identity before setting up a passkey.",
		`class="stepup-message-slot"`,
		`">Verify</a>`,
		"Back",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("passkey identity verification page missing %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{
		"Additional verification",
		"Confirm your identity provider sign-in before setting up a passkey.",
		"Continue with identity provider",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("passkey identity verification page should not contain %q: %s", forbidden, body)
		}
	}
}

func TestBrowserStepUpPasskeyCreatePageUsesAdminMFAStyle(t *testing.T) {
	server, _ := newDeviceAPITestServer(t)
	server.pa.Cfg.WebAuthnRPID = "localhost"
	server.pa.Cfg.WebAuthnRPName = "TrustCloud"
	server.pa.Cfg.WebAuthnRPOrigins = "https://localhost:8443"
	server.pa.Auth.WebAuthn = mfa.NewWebAuthnProvider(server.pa.Cfg)
	challenge := newStepUpBrowserChallenge(t, server, &models.User{
		ID:           "user-stepup",
		Username:     "alice@example.test",
		Email:        "alice@example.test",
		PasswordHash: testPasswordHash(t, "secret"),
		Role:         "user",
		TenantID:     transportTestTenantID,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}, []string{"webauthn"})

	req := httptest.NewRequest(http.MethodGet, "/browser/step-up/"+challenge.ID+"?method=webauthn", nil)
	rr := httptest.NewRecorder()
	server.handleBrowserStepUp(rr, req)
	csrf := csrfCookie(t, rr)

	authCookie := completeStepUpReauthForMethod(t, server, challenge, csrf, "webauthn", "secret")
	req = httptest.NewRequest(http.MethodGet, "/browser/step-up/"+challenge.ID+"?method=webauthn", nil)
	req.AddCookie(csrf)
	req.AddCookie(authCookie)
	rr = httptest.NewRecorder()
	server.handleBrowserStepUp(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{
		`class="panel stepup-panel passkey-create-stepup"`,
		"Set up passkey",
		"Create a passkey. The passkey will also complete this verification request.",
		`class="stepup-message-slot"`,
		`id="webauthn-status" class="webauthn-status"`,
		`id="webauthn-register-button">Create</button>`,
		"Back",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("passkey create page missing %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{
		"Create passkey",
		"Create a passkey for this user",
		"Create a passkey for this PDP user",
		`id="webauthn-register-button">Create passkey</button>`,
		`class="status"`,
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("passkey create page should not contain %q: %s", forbidden, body)
		}
	}
}

func TestBrowserStepUpCancelDeniesChallenge(t *testing.T) {
	server, _ := newDeviceAPITestServer(t)
	challenge := newStepUpBrowserChallenge(t, server, &models.User{
		ID:           "user-stepup",
		Username:     "alice@example.test",
		Email:        "alice@example.test",
		PasswordHash: testPasswordHash(t, "secret"),
		Role:         "user",
		TenantID:     transportTestTenantID,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}, []string{"totp"})

	req := httptest.NewRequest(http.MethodGet, "/browser/step-up/"+challenge.ID, nil)
	rr := httptest.NewRecorder()
	server.handleBrowserStepUp(rr, req)
	csrf := csrfCookie(t, rr)

	form := url.Values{}
	form.Set("csrf_token", csrf.Value)
	form.Set("action", "cancel")
	req = httptest.NewRequest(http.MethodPost, "/browser/step-up/"+challenge.ID, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrf)
	rr = httptest.NewRecorder()
	server.handleBrowserStepUp(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 body=%s", rr.Code, rr.Body.String())
	}
	if got, want := rr.Header().Get("Location"), "/browser/step-up/"+challenge.ID+"?cancelled=1"; got != want {
		t.Fatalf("redirect location = %q, want %q", got, want)
	}
	updated, ok := server.pa.StepUps.Get(challenge.ID)
	if !ok || updated.Status != pa.StepUpStatusDenied || updated.Reason != "user_cancelled" {
		t.Fatalf("challenge should be cancelled: %+v ok=%v", updated, ok)
	}

	req = httptest.NewRequest(http.MethodGet, rr.Header().Get("Location"), nil)
	rr = httptest.NewRecorder()
	server.handleBrowserStepUp(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Verification cancelled") || !strings.Contains(rr.Body.String(), `class="cancel-mark"`) {
		t.Fatalf("cancelled result status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestBrowserStepUpCompletedStatusUsesResourceRetryMessage(t *testing.T) {
	server, _ := newDeviceAPITestServer(t)
	challenge := newStepUpBrowserChallenge(t, server, &models.User{
		ID:           "user-stepup",
		Username:     "alice@example.test",
		Email:        "alice@example.test",
		PasswordHash: testPasswordHash(t, "secret"),
		Role:         "user",
		TenantID:     transportTestTenantID,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}, []string{"totp"})

	if _, err := server.pa.StepUps.Complete(challenge.ID, "totp", time.Now().UTC()); err != nil {
		t.Fatalf("complete step-up challenge: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/browser/step-up/"+challenge.ID+"?completed=1", nil)
	rr := httptest.NewRecorder()
	server.handleBrowserStepUp(rr, req)

	body := rr.Body.String()
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", rr.Code, body)
	}
	for _, want := range []string{
		"Verification complete",
		stepUpResourceCompleteMessage,
		`class="completion-mark"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("completed status page missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "go back to the TRUSTAgent app") {
		t.Fatalf("completed step-up page should not use TrustAgent login message: %s", body)
	}
}

func TestBrowserStepUpTOTPSetupCompletesChallenge(t *testing.T) {
	server, dataStore := newDeviceAPITestServer(t)
	challenge := newStepUpBrowserChallenge(t, server, &models.User{
		ID:           "user-stepup",
		Username:     "alice@example.test",
		Email:        "alice@example.test",
		PasswordHash: testPasswordHash(t, "secret"),
		Role:         "user",
		TenantID:     transportTestTenantID,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}, []string{"totp"})

	req := httptest.NewRequest(http.MethodGet, "/browser/step-up/"+challenge.ID+"?method=totp", nil)
	rr := httptest.NewRecorder()
	server.handleBrowserStepUp(rr, req)

	csrf := csrfCookie(t, rr)
	authCookie := completeStepUpReauth(t, server, challenge, csrf, "secret")

	req = httptest.NewRequest(http.MethodGet, "/browser/step-up/"+challenge.ID+"?method=totp", nil)
	req.AddCookie(csrf)
	req.AddCookie(authCookie)
	rr = httptest.NewRecorder()
	server.handleBrowserStepUp(rr, req)

	secret, ok := server.pa.StepUps.PendingTOTPSecret(challenge.ID)
	if !ok || strings.TrimSpace(secret) == "" {
		t.Fatalf("TOTP setup did not create pending challenge secret")
	}
	code, err := auth.GenerateTOTPCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}

	form := url.Values{}
	form.Set("csrf_token", csrf.Value)
	form.Set("method", "totp")
	form.Set("totp_code", code)
	req = httptest.NewRequest(http.MethodPost, "/browser/step-up/"+challenge.ID, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrf)
	req.AddCookie(authCookie)
	rr = httptest.NewRecorder()
	server.handleBrowserStepUp(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Verification complete") || !strings.Contains(body, `class="completion-mark"`) {
		t.Fatalf("completion page missing success message: %s", rr.Body.String())
	}
	if !strings.Contains(body, stepUpResourceCompleteMessage) {
		t.Fatalf("completion page missing resource retry message: %s", body)
	}
	if strings.Contains(body, "go back to the TRUSTAgent app") {
		t.Fatalf("resource step-up page should not use TrustAgent login message: %s", body)
	}
	user, ok := dataStore.GetUser("user-stepup")
	if !ok || !hasMFAMethod(user.MFAMethods, "totp") {
		t.Fatalf("TOTP was not activated: user=%+v ok=%v", user, ok)
	}
	completed, ok := server.pa.StepUps.Get(challenge.ID)
	if !ok || completed.Status != pa.StepUpStatusCompleted || completed.CompletedMethod != "totp" {
		t.Fatalf("challenge not completed via TOTP: %+v ok=%v", completed, ok)
	}
}

func TestBrowserStepUpReauthFailureUsesGlobalLockout(t *testing.T) {
	server, dataStore := newDeviceAPITestServer(t)
	server.pa.Cfg.MaxLoginAttempts = 2
	server.pa.Cfg.LockoutDuration = time.Hour
	challenge := newStepUpBrowserChallenge(t, server, &models.User{
		ID:           "user-stepup",
		Username:     "alice@example.test",
		Email:        "alice@example.test",
		PasswordHash: testPasswordHash(t, "secret"),
		Role:         "user",
		TenantID:     transportTestTenantID,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}, []string{"totp"})

	req := httptest.NewRequest(http.MethodGet, "/browser/step-up/"+challenge.ID+"?method=totp", nil)
	rr := httptest.NewRecorder()
	server.handleBrowserStepUp(rr, req)
	csrf := csrfCookie(t, rr)

	for i := 0; i < 2; i++ {
		form := url.Values{}
		form.Set("csrf_token", csrf.Value)
		form.Set("method", "reauth")
		form.Set("target_method", "totp")
		form.Set("password", "wrong")
		req = httptest.NewRequest(http.MethodPost, "/browser/step-up/"+challenge.ID, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(csrf)
		rr = httptest.NewRecorder()
		server.handleBrowserStepUp(rr, req)
	}

	if locked, _ := dataStore.IsLockedOut("alice@example.test"); !locked {
		t.Fatal("expected failed MFA re-authentication to lock the account globally")
	}
}

func TestStepUpCSPDisallowsInlineScripts(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/browser/step-up/stepup-1", nil)
	policy := contentSecurityPolicy(req, "'self'")
	if !strings.Contains(policy, "script-src 'self';") {
		t.Fatalf("step-up CSP did not restrict script-src to self: %s", policy)
	}
	if strings.Contains(policy, "script-src 'self' 'unsafe-inline'") {
		t.Fatalf("step-up CSP allows inline scripts: %s", policy)
	}
}

func TestStepUpWebAuthnClientMessagesAreGenericAlerts(t *testing.T) {
	for _, want := range []string{
		"page-alert stepup-alert",
		"Passkey setup failed. Try again.",
		"Passkey verification failed. Try again.",
		"clearStatus();",
	} {
		if !strings.Contains(stepUpBrowserJS, want) {
			t.Fatalf("step-up browser JS missing %q", want)
		}
	}
	for _, forbidden := range []string{
		"Creating passkey...",
		"Waiting for passkey...",
		"Verification complete.",
		"err.message",
		"readError(",
	} {
		if strings.Contains(stepUpBrowserJS, forbidden) {
			t.Fatalf("step-up browser JS should not contain %q", forbidden)
		}
	}
}

func newStepUpBrowserChallenge(t *testing.T, server *Server, user *models.User, methods []string) *pa.StepUpChallenge {
	t.Helper()
	server.pa.Store.SaveUser(user)
	challenge, err := server.pa.StepUps.CreateChallenge(pa.StepUpChallengeRequest{
		AgentSessionID: "agent-session-1",
		UserID:         user.ID,
		Username:       user.Username,
		TenantID:       user.TenantID,
		DeviceID:       "device-1",
		ResourceID:     "res-web",
		PublicOrigin:   "https://pdp.example.test",
		Requirement: &models.StepUpRequirement{
			Methods:       methods,
			MaxAgeSeconds: 300,
		},
	})
	if err != nil {
		t.Fatalf("create step-up challenge: %v", err)
	}
	return challenge
}

func completeStepUpReauth(t *testing.T, server *Server, challenge *pa.StepUpChallenge, csrf *http.Cookie, password string) *http.Cookie {
	t.Helper()
	return completeStepUpReauthForMethod(t, server, challenge, csrf, "totp", password)
}

func completeStepUpReauthForMethod(t *testing.T, server *Server, challenge *pa.StepUpChallenge, csrf *http.Cookie, targetMethod, password string) *http.Cookie {
	t.Helper()
	form := url.Values{}
	form.Set("csrf_token", csrf.Value)
	form.Set("method", "reauth")
	form.Set("target_method", targetMethod)
	form.Set("password", password)
	req := httptest.NewRequest(http.MethodPost, "/browser/step-up/"+challenge.ID, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrf)
	rr := httptest.NewRecorder()
	server.handleBrowserStepUp(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("reauth status = %d, want 303 body=%s", rr.Code, rr.Body.String())
	}
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == stepUpAuthCookieName && cookie.MaxAge > 0 {
			if cookie.Path != "/" {
				t.Fatalf("%s path = %q, want / so passkey setup API receives it", stepUpAuthCookieName, cookie.Path)
			}
			return cookie
		}
	}
	t.Fatalf("reauth did not set %s cookie", stepUpAuthCookieName)
	return nil
}

func csrfCookie(t *testing.T, rr *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == "csrf_token" {
			return cookie
		}
	}
	t.Fatal("response did not set csrf_token cookie")
	return nil
}

func testPasswordHash(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	return string(hash)
}
