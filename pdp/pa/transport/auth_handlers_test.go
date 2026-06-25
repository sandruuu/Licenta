package transport

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"pdp/models"
	paauth "pdp/pa/auth"

	"golang.org/x/crypto/bcrypt"
)

func TestAdminLoginRequiresPasswordChangeBeforeMFA(t *testing.T) {
	server, dataStore := newDeviceAPITestServer(t)
	savePasswordChangeTestUser(t, dataStore, "usr_initial_password", "initial-admin@example.test", "temporary-password-123", true)

	body := bytes.NewBufferString(`{"email":"initial-admin@example.test","password":"temporary-password-123"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", body)
	rr := httptest.NewRecorder()
	server.handleLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("login status = %d body=%s, want %d", rr.Code, rr.Body.String(), http.StatusOK)
	}
	var response models.LoginResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if response.Status != "password_change_required" || !response.PasswordChangeRequired {
		t.Fatalf("unexpected login response: %+v", response)
	}
	if response.ChallengeID == "" {
		t.Fatalf("password change challenge was not returned")
	}
	if response.AuthToken != "" || response.RefreshToken != "" || response.SessionID != "" || response.MFARequired {
		t.Fatalf("login with temporary password must not create session or MFA flow: %+v", response)
	}
}

func TestInitialPasswordChangeAllowsNextLoginToContinueToMFA(t *testing.T) {
	server, dataStore := newDeviceAPITestServer(t)
	user := savePasswordChangeTestUser(t, dataStore, "usr_change_password", "change-admin@example.test", "temporary-password-123", true)

	loginResponse := loginPasswordChangeRequiredForTest(t, server, user.Email, "temporary-password-123")

	changeBody := bytes.NewBufferString(`{"challenge_id":"` + loginResponse.ChallengeID + `","new_password":"new-secure-password-123","confirm_password":"new-secure-password-123"}`)
	changeReq := httptest.NewRequest(http.MethodPost, "/api/auth/password/change-initial", changeBody)
	changeRR := httptest.NewRecorder()
	server.handleInitialPasswordChange(changeRR, changeReq)
	if changeRR.Code != http.StatusOK {
		t.Fatalf("password change status = %d body=%s, want %d", changeRR.Code, changeRR.Body.String(), http.StatusOK)
	}

	updated, ok := dataStore.GetUser(user.ID)
	if !ok {
		t.Fatalf("updated user not found")
	}
	if updated.PasswordChangeRequired {
		t.Fatalf("password_change_required was not cleared")
	}
	if updated.PasswordChangedAt.IsZero() {
		t.Fatalf("password_changed_at was not set")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(updated.PasswordHash), []byte("new-secure-password-123")); err != nil {
		t.Fatalf("new password hash does not match: %v", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(updated.PasswordHash), []byte("temporary-password-123")) == nil {
		t.Fatalf("temporary password still matches after password change")
	}

	nextBody := bytes.NewBufferString(`{"email":"change-admin@example.test","password":"new-secure-password-123"}`)
	nextReq := httptest.NewRequest(http.MethodPost, "/api/auth/login", nextBody)
	nextRR := httptest.NewRecorder()
	server.handleLogin(nextRR, nextReq)
	if nextRR.Code != http.StatusOK {
		t.Fatalf("next login status = %d body=%s, want %d", nextRR.Code, nextRR.Body.String(), http.StatusOK)
	}
	var nextResponse models.LoginResponse
	if err := json.NewDecoder(nextRR.Body).Decode(&nextResponse); err != nil {
		t.Fatalf("decode next login response: %v", err)
	}
	if nextResponse.Status != "mfa_setup_required" || !nextResponse.MFARequired || !nextResponse.MFASetup {
		t.Fatalf("next login did not continue to MFA setup: %+v", nextResponse)
	}
}

func TestInitialPasswordChangeReturnsPasswordPolicyDetails(t *testing.T) {
	server, dataStore := newDeviceAPITestServer(t)
	user := savePasswordChangeTestUser(t, dataStore, "usr_policy_details", "policy-details@example.test", "temporary-password-123", true)

	loginResponse := loginPasswordChangeRequiredForTest(t, server, user.Email, "temporary-password-123")

	body := bytes.NewBufferString(`{"challenge_id":"` + loginResponse.ChallengeID + `","new_password":"short password","confirm_password":"short password"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password/change-initial", body)
	rr := httptest.NewRecorder()
	server.handleInitialPasswordChange(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("password policy status = %d body=%s, want %d", rr.Code, rr.Body.String(), http.StatusBadRequest)
	}

	var response struct {
		Error                string   `json:"error"`
		PasswordRequirements []string `json:"password_requirements"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("decode policy response: %v", err)
	}
	if !strings.Contains(response.Error, "at least 15") {
		t.Fatalf("policy error = %q, want minimum length detail", response.Error)
	}
	if len(response.PasswordRequirements) == 0 {
		t.Fatalf("password policy response did not include requirements")
	}
}

func TestMFASetupGeneratesRecoveryCodesOnce(t *testing.T) {
	server, dataStore := newDeviceAPITestServer(t)
	savePasswordChangeTestUser(t, dataStore, "usr_mfa_recovery_setup", "mfa-recovery@example.test", "secure-password-123", false)

	setupResponse := loginMFASetupForTest(t, server, "mfa-recovery@example.test", "secure-password-123")
	code, err := paauth.GenerateTOTPCode(setupResponse.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}
	verifyResponse := verifyMFACodeForTest(t, server, setupResponse.ChallengeID, code)

	if verifyResponse.AuthToken == "" || len(verifyResponse.RecoveryCodes) != 10 {
		t.Fatalf("MFA setup response missing token or recovery codes: %+v", verifyResponse)
	}
	activeCodes, err := dataStore.ListActiveMFARecoveryCodes("usr_mfa_recovery_setup")
	if err != nil {
		t.Fatalf("list recovery codes: %v", err)
	}
	if len(activeCodes) != len(verifyResponse.RecoveryCodes) {
		t.Fatalf("stored recovery code count = %d, want %d", len(activeCodes), len(verifyResponse.RecoveryCodes))
	}
	seen := map[string]bool{}
	for _, code := range verifyResponse.RecoveryCodes {
		if seen[code] {
			t.Fatalf("duplicate recovery code returned: %s", code)
		}
		seen[code] = true
		for _, stored := range activeCodes {
			if stored.CodeHash == code {
				t.Fatalf("recovery code stored in plaintext")
			}
		}
	}
}

func TestRecoveryCodeStartsMFAResetAndCannotBeReused(t *testing.T) {
	server, dataStore := newDeviceAPITestServer(t)
	savePasswordChangeTestUser(t, dataStore, "usr_mfa_recovery_use", "mfa-recovery-use@example.test", "secure-password-123", false)

	setupResponse := loginMFASetupForTest(t, server, "mfa-recovery-use@example.test", "secure-password-123")
	code, err := paauth.GenerateTOTPCode(setupResponse.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}
	verifyResponse := verifyMFACodeForTest(t, server, setupResponse.ChallengeID, code)
	recoveryCode := verifyResponse.RecoveryCodes[0]

	mfaResponse := loginMFARequiredForTest(t, server, "mfa-recovery-use@example.test", "secure-password-123")
	recoveryResponse := verifyRecoveryCodeForTest(t, server, mfaResponse.ChallengeID, recoveryCode)
	if recoveryResponse.AuthToken != "" || !recoveryResponse.MFASetup || !recoveryResponse.RecoveryUsed || recoveryResponse.Secret == "" {
		t.Fatalf("recovery code should start MFA setup without issuing a session: %+v", recoveryResponse)
	}

	activeCodes, err := dataStore.ListActiveMFARecoveryCodes("usr_mfa_recovery_use")
	if err != nil {
		t.Fatalf("list recovery codes: %v", err)
	}
	if len(activeCodes) != len(verifyResponse.RecoveryCodes)-1 {
		t.Fatalf("active recovery code count = %d, want %d", len(activeCodes), len(verifyResponse.RecoveryCodes)-1)
	}

	reuseLogin := loginMFARequiredForTest(t, server, "mfa-recovery-use@example.test", "secure-password-123")
	reuseBody := bytes.NewBufferString(`{"challenge_id":"` + reuseLogin.ChallengeID + `","recovery_code":"` + recoveryCode + `"}`)
	reuseReq := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/recovery", reuseBody)
	reuseRR := httptest.NewRecorder()
	server.handleMFARecovery(reuseRR, reuseReq)
	if reuseRR.Code != http.StatusUnauthorized {
		t.Fatalf("reused recovery code status = %d body=%s, want %d", reuseRR.Code, reuseRR.Body.String(), http.StatusUnauthorized)
	}
}

func TestAdminAccountPasswordChange(t *testing.T) {
	server, dataStore := newDeviceAPITestServer(t)
	user := savePasswordChangeTestUser(t, dataStore, "usr_account_password", "account-password@example.test", "secure-password-123", false)
	loginResponse, err := server.startAdminSession(user, "Authentication successful")
	if err != nil {
		t.Fatalf("startAdminSession: %v", err)
	}

	body := bytes.NewBufferString(`{"current_password":"secure-password-123","new_password":"new-secure-password-456","confirm_password":"new-secure-password-456"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/account/password", body)
	req.Header.Set("Authorization", "Bearer "+loginResponse.AuthToken)
	rr := httptest.NewRecorder()
	server.adminAuthMiddleware(http.HandlerFunc(server.handleAdminAccountPassword)).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("password change status = %d body=%s, want %d", rr.Code, rr.Body.String(), http.StatusOK)
	}

	updated, ok := dataStore.GetUser(user.ID)
	if !ok {
		t.Fatalf("updated user not found")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(updated.PasswordHash), []byte("new-secure-password-456")); err != nil {
		t.Fatalf("new password hash does not match: %v", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(updated.PasswordHash), []byte("secure-password-123")) == nil {
		t.Fatalf("old password still matches after account password change")
	}
	if updated.PasswordChangedAt.IsZero() {
		t.Fatalf("password_changed_at was not set")
	}
}

func TestAdminAccountRecoveryCodeRegenerationRequiresPassword(t *testing.T) {
	server, dataStore := newDeviceAPITestServer(t)
	user := savePasswordChangeTestUser(t, dataStore, "usr_account_recovery", "account-recovery@example.test", "secure-password-123", false)
	user.MFAMethods = []string{"totp"}
	dataStore.SaveUser(user)
	loginResponse, err := server.startAdminSession(user, "Authentication successful")
	if err != nil {
		t.Fatalf("startAdminSession: %v", err)
	}

	wrongBody := bytes.NewBufferString(`{"current_password":"wrong-password"}`)
	wrongReq := httptest.NewRequest(http.MethodPost, "/api/admin/account/recovery-codes", wrongBody)
	wrongReq.Header.Set("Authorization", "Bearer "+loginResponse.AuthToken)
	wrongRR := httptest.NewRecorder()
	server.adminAuthMiddleware(http.HandlerFunc(server.handleAdminAccountRecoveryCodes)).ServeHTTP(wrongRR, wrongReq)
	if wrongRR.Code != http.StatusBadRequest {
		t.Fatalf("wrong password status = %d body=%s, want %d", wrongRR.Code, wrongRR.Body.String(), http.StatusBadRequest)
	}

	body := bytes.NewBufferString(`{"current_password":"secure-password-123"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/account/recovery-codes", body)
	req.Header.Set("Authorization", "Bearer "+loginResponse.AuthToken)
	rr := httptest.NewRecorder()
	server.adminAuthMiddleware(http.HandlerFunc(server.handleAdminAccountRecoveryCodes)).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("recovery regeneration status = %d body=%s, want %d", rr.Code, rr.Body.String(), http.StatusOK)
	}
	var response struct {
		Success bool `json:"success"`
		Data    struct {
			RecoveryCodes []string `json:"recovery_codes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("decode recovery response: %v", err)
	}
	if !response.Success || len(response.Data.RecoveryCodes) != 10 {
		t.Fatalf("unexpected recovery response: %+v", response)
	}
	activeCodes, err := dataStore.ListActiveMFARecoveryCodes(user.ID)
	if err != nil {
		t.Fatalf("list recovery codes: %v", err)
	}
	if len(activeCodes) != len(response.Data.RecoveryCodes) {
		t.Fatalf("stored recovery code count = %d, want %d", len(activeCodes), len(response.Data.RecoveryCodes))
	}
}

func loginPasswordChangeRequiredForTest(t *testing.T, server *Server, email, password string) models.LoginResponse {
	t.Helper()
	body := bytes.NewBufferString(`{"email":"` + email + `","password":"` + password + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", body)
	rr := httptest.NewRecorder()
	server.handleLogin(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login status = %d body=%s, want %d", rr.Code, rr.Body.String(), http.StatusOK)
	}
	var response models.LoginResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if response.Status != "password_change_required" || response.ChallengeID == "" {
		t.Fatalf("unexpected password change response: %+v", response)
	}
	return response
}

func loginMFASetupForTest(t *testing.T, server *Server, email, password string) models.LoginResponse {
	t.Helper()
	body := bytes.NewBufferString(`{"email":"` + email + `","password":"` + password + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", body)
	rr := httptest.NewRecorder()
	server.handleLogin(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login status = %d body=%s, want %d", rr.Code, rr.Body.String(), http.StatusOK)
	}
	var response models.LoginResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if response.Status != "mfa_setup_required" || !response.MFASetup || response.Secret == "" {
		t.Fatalf("unexpected MFA setup response: %+v", response)
	}
	return response
}

func loginMFARequiredForTest(t *testing.T, server *Server, email, password string) models.LoginResponse {
	t.Helper()
	body := bytes.NewBufferString(`{"email":"` + email + `","password":"` + password + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", body)
	rr := httptest.NewRecorder()
	server.handleLogin(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login status = %d body=%s, want %d", rr.Code, rr.Body.String(), http.StatusOK)
	}
	var response models.LoginResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if response.Status != "mfa_required" || !response.MFARequired || response.ChallengeID == "" {
		t.Fatalf("unexpected MFA required response: %+v", response)
	}
	return response
}

func verifyMFACodeForTest(t *testing.T, server *Server, challengeID, code string) models.LoginResponse {
	t.Helper()
	body := bytes.NewBufferString(`{"challenge_id":"` + challengeID + `","code":"` + code + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/verify", body)
	rr := httptest.NewRecorder()
	server.handleMFAVerify(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("MFA verify status = %d body=%s, want %d", rr.Code, rr.Body.String(), http.StatusOK)
	}
	var response models.LoginResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("decode MFA verify response: %v", err)
	}
	return response
}

func verifyRecoveryCodeForTest(t *testing.T, server *Server, challengeID, code string) models.LoginResponse {
	t.Helper()
	body := bytes.NewBufferString(`{"challenge_id":"` + challengeID + `","recovery_code":"` + code + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/recovery", body)
	rr := httptest.NewRecorder()
	server.handleMFARecovery(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("MFA recovery status = %d body=%s, want %d", rr.Code, rr.Body.String(), http.StatusOK)
	}
	var response models.LoginResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("decode MFA recovery response: %v", err)
	}
	return response
}

func savePasswordChangeTestUser(t *testing.T, dataStore interface {
	SaveUser(*models.User)
}, id, email, password string, passwordChangeRequired bool) *models.User {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	now := time.Now().UTC()
	user := &models.User{
		ID:                     id,
		Username:               email,
		Email:                  email,
		PasswordHash:           string(hash),
		PasswordChangeRequired: passwordChangeRequired,
		MFAMethods:             []string{},
		Role:                   "platform_admin",
		LastTOTPCounter:        -1,
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	dataStore.SaveUser(user)
	return user
}
