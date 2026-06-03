package transport

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

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
	for _, want := range []string{"Authenticator app", "Set up required", "Confirm your PDP password"} {
		if !strings.Contains(body, want) {
			t.Fatalf("step-up page missing %q: %s", want, body)
		}
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
	for _, want := range []string{"Can't scan? Show setup key", "Set up and verify"} {
		if !strings.Contains(body, want) {
			t.Fatalf("authorized setup page missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "Open setup link") {
		t.Fatalf("authorized setup page should not expose the setup link: %s", body)
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
	if !strings.Contains(rr.Body.String(), "Verification complete") {
		t.Fatalf("completion page missing success message: %s", rr.Body.String())
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
	form := url.Values{}
	form.Set("csrf_token", csrf.Value)
	form.Set("method", "reauth")
	form.Set("target_method", "totp")
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
