package transport

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"pdp/models"
	paauth "pdp/pa/auth"
	"pdp/util"
)

type adminPasskeyLoginBeginRequest struct {
	Email string `json:"email"`
}

type adminPasskeySecretRequest struct {
	CurrentPassword string `json:"current_password"`
}

type adminPasskeyResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}

func (s *Server) handleAdminAccountPasskeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		user, ok := s.currentAdminUser(w, r)
		if !ok {
			return
		}
		creds, err := s.pa.Store.GetWebAuthnCredentials(user.ID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load passkeys"})
			return
		}
		writeJSON(w, http.StatusOK, models.APIResponse{
			Success: true,
			Data:    adminPasskeyPayload(creds),
		})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleAdminAccountPasskeyAction(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/admin/account/passkeys/"), "/")
	if path == "enrollment-token" {
		s.handleAdminAccountPasskeyEnrollmentToken(w, r)
		return
	}
	if path == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "passkey not found"})
		return
	}
	s.handleAdminAccountPasskeyByID(w, r, path)
}

func (s *Server) handleAdminAccountPasskeyEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	user, ok := s.currentAdminUser(w, r)
	if !ok {
		return
	}
	if s.pa.Auth.WebAuthn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "passkey registration is not configured"})
		return
	}
	var req adminPasskeySecretRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if err := s.pa.Auth.Users.VerifyPassword(user.ID, req.CurrentPassword); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	token, err := s.pa.Auth.JWT.GenerateAuthTokenWithPurpose(user.ID, user.Username, user.Role, "", "", true, paauth.PasskeyEnrollmentPurpose)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to start passkey registration"})
		return
	}
	if s.pa.Audit != nil {
		s.pa.Audit.LogEvent("admin_passkey_enrollment_started", user.ID, user.Username, r.RemoteAddr, "", "", "Dashboard passkey enrollment started from account settings", true)
	}
	writeJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Data: map[string]string{
			"auth_token": token,
			"purpose":    paauth.PasskeyEnrollmentPurpose,
		},
	})
}

func (s *Server) handleAdminAccountPasskeyByID(w http.ResponseWriter, r *http.Request, passkeyID string) {
	if r.Method != http.MethodDelete {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	user, ok := s.currentAdminUser(w, r)
	if !ok {
		return
	}
	var req adminPasskeySecretRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if err := s.pa.Auth.Users.VerifyPassword(user.ID, req.CurrentPassword); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	creds, err := s.pa.Store.GetWebAuthnCredentials(user.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load passkeys"})
		return
	}
	found := false
	for _, cred := range creds {
		if cred != nil && cred.ID == passkeyID {
			found = true
			break
		}
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "passkey not found"})
		return
	}
	if err := s.pa.Store.DeleteWebAuthnCredential(passkeyID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to delete passkey"})
		return
	}
	remaining, err := s.pa.Store.GetWebAuthnCredentials(user.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load passkeys"})
		return
	}
	if len(remaining) == 0 {
		s.pa.Auth.Users.RemoveMFAMethod(user.ID, "webauthn")
	}
	if s.pa.Audit != nil {
		s.pa.Audit.LogEvent("admin_passkey_deleted", user.ID, user.Username, r.RemoteAddr, "", "", "Dashboard passkey deleted from account settings", true)
	}
	writeJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Passkey deleted",
		Data:    adminPasskeyPayload(remaining),
	})
}

func adminPasskeyPayload(creds []*models.WebAuthnCredential) []adminPasskeyResponse {
	response := make([]adminPasskeyResponse, 0, len(creds))
	for _, cred := range creds {
		if cred == nil {
			continue
		}
		createdAt := ""
		if !cred.CreatedAt.IsZero() {
			createdAt = cred.CreatedAt.Format("2006-01-02 15:04:05")
		}
		name := strings.TrimSpace(cred.Name)
		if name == "" {
			name = "Passkey"
		}
		response = append(response, adminPasskeyResponse{
			ID:        cred.ID,
			Name:      name,
			CreatedAt: createdAt,
		})
	}
	return response
}

func (s *Server) handleAdminPasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	user, claims, ok := s.authenticatePasskeyEnrollmentRequest(w, r)
	if !ok {
		return
	}
	if s.pa.Auth.WebAuthn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "passkey registration is not configured"})
		return
	}
	existingCreds, err := s.loadWebAuthnCredentials(user.ID)
	if err != nil {
		log.Printf("[AUTH] Admin passkey credential load failed: user=%s err=%v", user.ID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load passkey credentials"})
		return
	}
	opts, err := s.pa.Auth.WebAuthn.BeginRegistration(user, existingCreds, claims.ID)
	if err != nil {
		log.Printf("[AUTH] Admin passkey registration begin failed: user=%s err=%v", user.ID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to start passkey registration"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(opts)
}

func (s *Server) handleAdminPasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	user, claims, ok := s.authenticatePasskeyEnrollmentRequest(w, r)
	if !ok {
		return
	}
	if s.pa.Auth.WebAuthn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "passkey registration is not configured"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxStepUpRequestBody)
	existingCreds, err := s.loadWebAuthnCredentials(user.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load passkey credentials"})
		return
	}
	cred, err := s.pa.Auth.WebAuthn.FinishRegistration(user, existingCreds, claims.ID, r)
	if err != nil {
		log.Printf("[AUTH] Admin passkey registration finish failed: user=%s err=%v", user.ID, err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passkey registration failed"})
		return
	}
	credJSON, _ := json.Marshal(cred)
	credentialJSON := string(credJSON)
	if protected, err := s.pa.Auth.Users.ProtectMFAValue(credentialJSON); err == nil {
		credentialJSON = protected
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
		log.Printf("[AUTH] Admin passkey credential save failed: user=%s err=%v", user.ID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save passkey"})
		return
	}
	s.pa.Auth.Users.AddMFAMethod(user.ID, "webauthn")
	if s.pa.Audit != nil {
		s.pa.Audit.LogEvent("admin_passkey_enrolled", user.ID, user.Username, r.RemoteAddr, "", "", "Dashboard passkey enrolled after password and Authenticator app verification", true)
	}
	response, err := s.startAdminSession(user, "Passkey registered")
	if err != nil {
		log.Printf("[AUTH] Admin session start after passkey enrollment failed: user=%s err=%v", user.ID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authentication failed"})
		return
	}
	s.writeAdminSessionResponse(w, http.StatusOK, response)
}

func (s *Server) handleAdminPasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.checkAuthRateLimit(w, r) {
		return
	}
	if s.pa.Auth.WebAuthn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "passkey sign-in is not configured"})
		return
	}

	var req adminPasskeyLoginBeginRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	email := strings.TrimSpace(req.Email)
	if email == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email is required"})
		return
	}

	user, exists := s.pa.Auth.Users.GetUserByEmail(email)
	if !exists || user == nil || user.Disabled || user.Role != "platform_admin" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "passkey sign-in is not configured for this account"})
		return
	}
	if user.PasswordChangeRequired {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "password change required"})
		return
	}
	creds, err := s.loadWebAuthnCredentials(user.ID)
	if err != nil {
		log.Printf("[AUTH] Admin passkey login credential load failed: user=%s err=%v", user.ID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load passkey credentials"})
		return
	}
	if len(creds) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "passkey sign-in is not configured for this account"})
		return
	}

	challengeID, err := util.GenerateID("wla")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to start passkey sign-in"})
		return
	}
	opts, err := s.pa.Auth.WebAuthn.BeginAuthentication(user, creds, challengeID)
	if err != nil {
		log.Printf("[AUTH] Admin passkey login begin failed: user=%s err=%v", user.ID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to start passkey sign-in"})
		return
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(opts, &payload); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to start passkey sign-in"})
		return
	}
	payload["challenge_id"] = challengeID
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleAdminPasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.checkAuthRateLimit(w, r) {
		return
	}
	if s.pa.Auth.WebAuthn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "passkey sign-in is not configured"})
		return
	}

	challengeID := strings.TrimSpace(r.URL.Query().Get("challenge_id"))
	email := strings.TrimSpace(r.URL.Query().Get("email"))
	if challengeID == "" || email == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passkey sign-in session is missing"})
		return
	}
	user, exists := s.pa.Auth.Users.GetUserByEmail(email)
	if !exists || user == nil || user.Disabled || user.Role != "platform_admin" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "passkey sign-in failed"})
		return
	}
	if user.PasswordChangeRequired {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "password change required"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxStepUpRequestBody)
	creds, err := s.loadWebAuthnCredentials(user.ID)
	if err != nil || len(creds) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passkey sign-in is not configured for this account"})
		return
	}
	updatedCred, err := s.pa.Auth.WebAuthn.FinishAuthentication(user, creds, challengeID, r)
	if err != nil {
		log.Printf("[AUTH] Admin passkey login finish failed: user=%s err=%v", user.ID, err)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "passkey sign-in failed"})
		return
	}
	credJSON, _ := json.Marshal(updatedCred)
	credentialJSON := string(credJSON)
	if protected, err := s.pa.Auth.Users.ProtectMFAValue(credentialJSON); err == nil {
		credentialJSON = protected
	}
	if err := s.pa.Store.UpdateWebAuthnCredentialJSON(hex.EncodeToString(updatedCred.ID), credentialJSON); err != nil {
		log.Printf("[AUTH] Admin passkey credential update failed: user=%s credential=%x err=%v", user.ID, updatedCred.ID, err)
	}
	_ = s.pa.Runtime.ResetLoginAttempts(email)
	if s.pa.Audit != nil {
		s.pa.Audit.LogEvent("admin_passkey_login", user.ID, user.Username, r.RemoteAddr, "", "", "Dashboard passkey sign-in completed", true)
	}
	response, err := s.startAdminSession(user, "Authentication successful")
	if err != nil {
		log.Printf("[AUTH] Admin session start after passkey login failed: user=%s err=%v", user.ID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authentication failed"})
		return
	}
	s.writeAdminSessionResponse(w, http.StatusOK, response)
}

func (s *Server) authenticatePasskeyEnrollmentRequest(w http.ResponseWriter, r *http.Request) (*models.User, *paauth.CustomClaims, bool) {
	token, err := bearerToken(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "passkey enrollment token required"})
		return nil, nil, false
	}
	claims, err := s.pa.Auth.ValidateToken(token)
	if err != nil || claims == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired passkey enrollment token"})
		return nil, nil, false
	}
	if claims.ID != "" && s.pa.Store.IsTokenRevoked(claims.ID) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "token has been revoked"})
		return nil, nil, false
	}
	if strings.TrimSpace(claims.Purpose) != paauth.PasskeyEnrollmentPurpose {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "token is not valid for passkey enrollment"})
		return nil, nil, false
	}
	if claims.Role != "platform_admin" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "platform administrator access required"})
		return nil, nil, false
	}
	user, exists := s.pa.Auth.Users.GetUser(claims.UserID)
	if !exists || user == nil || user.Disabled {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user is not available"})
		return nil, nil, false
	}
	if user.PasswordChangeRequired {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "password change required"})
		return nil, nil, false
	}
	return user, claims, true
}
