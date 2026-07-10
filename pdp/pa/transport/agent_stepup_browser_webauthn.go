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
	"pdp/pa"
	"pdp/util"
)

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
			s.logResourceStepUpEvent("agent_step_up_denied", challenge, stepUpRemoteIP(r), models.DecisionDeny, "Resource step-up denied after too many failed passkey attempts", false)
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
		s.pa.Audit.LogEvent("agent_step_up_completed", completed.UserID, completed.Username, stepUpRemoteIP(r), completed.ResourceID, models.DecisionAllow, stepUpAuditDetails(completed, "Step-up completed via Passkey"), true)
	}
	s.publishStepUpCompletedEvent(completed)
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
			s.logResourceStepUpEvent("agent_step_up_denied", challenge, stepUpRemoteIP(r), models.DecisionDeny, "Resource step-up denied after too many failed passkey setup attempts", false)
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
	recoveryCodes, err := s.recoveryCodesForStepUpMFAEnrollment(user.ID)
	if err != nil {
		log.Printf("[STEP-UP] Recovery code generation failed after WebAuthn enrollment: challenge=%s user=%s err=%v", challenge.ID, user.ID, err)
	}
	if s.pa.Audit != nil {
		s.pa.Audit.LogEvent("agent_mfa_enrolled", user.ID, user.Username, r.RemoteAddr, challenge.ResourceID, models.DecisionAllow, "Passkey enrolled during resource step-up", true)
	}
	completed, err := s.pa.StepUps.CompleteWithAssurance(challenge.ID, stepUpCompletionFromWebAuthn(cred), time.Now().UTC())
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "step-up challenge could not be completed"})
		return
	}
	if s.pa.Audit != nil {
		s.pa.Audit.LogEvent("agent_step_up_completed", completed.UserID, completed.Username, stepUpRemoteIP(r), completed.ResourceID, models.DecisionAllow, stepUpAuditDetails(completed, "Step-up completed via Passkey enrollment"), true)
	}
	s.publishStepUpCompletedEvent(completed)
	log.Printf("[STEP-UP] WebAuthn enrolled and completed challenge=%s user=%s resource=%s expires=%s", completed.ID, completed.UserID, completed.ResourceID, completed.ExpiresAt.Format(time.RFC3339))
	response := map[string]any{"status": "completed"}
	if len(recoveryCodes) > 0 {
		response["recovery_codes"] = recoveryCodes
	}
	writeJSON(w, http.StatusOK, response)
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
	if stepUpChallengeExpired(challenge, time.Now().UTC()) {
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

func stepUpChallengeExpired(challenge *pa.StepUpChallenge, now time.Time) bool {
	if challenge == nil || challenge.ExpiresAt.IsZero() {
		return false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return !now.UTC().Before(challenge.ExpiresAt.UTC())
}

func renderStepUpExpiredPage(w http.ResponseWriter) {
	renderEnrollmentPage(w, "Verification expired", "Try accessing the protected resource again.", "", false)
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
