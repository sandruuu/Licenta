package transport

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"pdp/models"
	"pdp/util"

	"github.com/go-webauthn/webauthn/webauthn"
)

// ─────────────────────────────────────────────
// WebAuthn endpoints
// ─────────────────────────────────────────────

// POST /api/mfa/webauthn/register/begin — requires JWT auth
// Starts the WebAuthn credential registration ceremony.
func (s *Server) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if s.pa.Auth.WebAuthn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "WebAuthn not configured"})
		return
	}

	userID := r.Header.Get("X-User-ID")
	user, exists := s.pa.Auth.Users.GetUser(userID)
	if !exists {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
		return
	}

	existingCreds, err := s.loadWebAuthnCredentials(userID)
	if err != nil {
		log.Printf("[WEBAUTHN] Failed to load credentials for %s: %v", userID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	opts, err := s.pa.Auth.WebAuthn.BeginRegistration(user, existingCreds)
	if err != nil {
		log.Printf("[WEBAUTHN] BeginRegistration error for %s: %v", user.Username, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to start registration"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(opts)
}

// POST /api/mfa/webauthn/register/finish — requires JWT auth
// Completes the WebAuthn credential registration ceremony.
func (s *Server) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if s.pa.Auth.WebAuthn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "WebAuthn not configured"})
		return
	}

	userID := r.Header.Get("X-User-ID")
	user, exists := s.pa.Auth.Users.GetUser(userID)
	if !exists {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
		return
	}

	existingCreds, err := s.loadWebAuthnCredentials(userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	cred, err := s.pa.Auth.WebAuthn.FinishRegistration(user, existingCreds, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "registration failed", err)
		return
	}

	// Persist the credential
	credJSON, _ := json.Marshal(cred)
	credID, _ := util.GenerateID("wc")

	// Read optional friendly name from query param
	credName := r.URL.Query().Get("name")
	if credName == "" {
		credName = "Passkey"
	}

	dbCred := &models.WebAuthnCredential{
		ID:             credID,
		UserID:         userID,
		CredentialID:   hex.EncodeToString(cred.ID),
		CredentialJSON: string(credJSON),
		Name:           credName,
		CreatedAt:      time.Now(),
	}

	if err := s.pa.Store.SaveWebAuthnCredential(dbCred); err != nil {
		log.Printf("[WEBAUTHN] Failed to save credential for %s: %v", user.Username, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save credential"})
		return
	}

	// Add "webauthn" to user's MFA methods if not already present
	s.pa.Auth.Users.AddMFAMethod(userID, "webauthn")

	log.Printf("[WEBAUTHN] Credential registered for user %s (name=%s)", user.Username, credName)
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"message": "Passkey registered successfully",
		"name":    credName,
	})
}

// POST /api/mfa/webauthn/authenticate/begin — uses MFA token (no full JWT auth)
// Starts the WebAuthn authentication ceremony during MFA step-up.
func (s *Server) handleWebAuthnAuthenticateBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if s.pa.Auth.WebAuthn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "WebAuthn not configured"})
		return
	}

	var body struct {
		MFAToken string `json:"mfa_token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	claims, err := s.pa.Auth.JWT.ValidateMFAToken(body.MFAToken)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid MFA token"})
		return
	}

	user, exists := s.pa.Auth.Users.GetUser(claims.UserID)
	if !exists {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
		return
	}

	creds, err := s.loadWebAuthnCredentials(claims.UserID)
	if err != nil || len(creds) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no WebAuthn credentials registered"})
		return
	}

	opts, err := s.pa.Auth.WebAuthn.BeginAuthentication(user, creds)
	if err != nil {
		log.Printf("[WEBAUTHN] BeginAuthentication error for %s: %v", user.Username, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to start authentication"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(opts)
}

// POST /api/mfa/webauthn/authenticate/finish — uses MFA token
// Completes the WebAuthn authentication ceremony (MFA verification).
func (s *Server) handleWebAuthnAuthenticateFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if s.pa.Auth.WebAuthn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "WebAuthn not configured"})
		return
	}

	// The MFA token is passed as a query param since the body is the
	// authenticator response that go-webauthn reads from r.Body.
	mfaToken := r.URL.Query().Get("mfa_token")
	if mfaToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mfa_token required"})
		return
	}

	claims, err := s.pa.Auth.JWT.ValidateMFAToken(mfaToken)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid MFA token"})
		return
	}

	user, exists := s.pa.Auth.Users.GetUser(claims.UserID)
	if !exists {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
		return
	}

	creds, err := s.loadWebAuthnCredentials(claims.UserID)
	if err != nil || len(creds) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no WebAuthn credentials registered"})
		return
	}

	updatedCred, err := s.pa.Auth.WebAuthn.FinishAuthentication(user, creds, r)
	if err != nil {
		log.Printf("[WEBAUTHN] FinishAuthentication error for %s: %v", user.Username, err)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "WebAuthn verification failed"})
		return
	}

	// Update the credential's sign count in the database
	credJSON, _ := json.Marshal(updatedCred)
	s.pa.Store.UpdateWebAuthnCredentialJSON(hex.EncodeToString(updatedCred.ID), string(credJSON))

	// Issue full auth token with MFA completed
	authToken, err := s.pa.Auth.JWT.GenerateAuthToken(user.ID, user.Username, user.Role, "", "", true)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token generation failed"})
		return
	}

	log.Printf("[WEBAUTHN] MFA verified via WebAuthn for user %s", user.Username)
	writeJSON(w, http.StatusOK, models.MFAVerifyResponse{
		Status:    "authenticated",
		Message:   "WebAuthn authentication successful",
		AuthToken: authToken,
	})
}

// loadWebAuthnCredentials loads and deserialises all WebAuthn credentials for a user.
func (s *Server) loadWebAuthnCredentials(userID string) ([]webauthn.Credential, error) {
	dbCreds, err := s.pa.Store.GetWebAuthnCredentials(userID)
	if err != nil {
		return nil, err
	}
	creds := make([]webauthn.Credential, 0, len(dbCreds))
	for _, dc := range dbCreds {
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(dc.CredentialJSON), &c); err != nil {
			log.Printf("[WEBAUTHN] Corrupt credential %s: %v", dc.ID, err)
			continue
		}
		creds = append(creds, c)
	}
	return creds, nil
}
