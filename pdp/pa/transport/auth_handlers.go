package transport

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"pdp/models"
)

// ─────────────────────────────────────────────
// Authentication endpoints
// ─────────────────────────────────────────────

// checkAuthRateLimit enforces per-IP rate limiting on authentication endpoints.
// Returns true if the request should be rejected (rate limit exceeded).
func (s *Server) checkAuthRateLimit(w http.ResponseWriter, r *http.Request) bool {
	ip, _, _ := strings.Cut(r.RemoteAddr, ":")
	s.authLimiterMu.Lock()
	defer s.authLimiterMu.Unlock()

	entry, ok := s.authLimiter[ip]
	now := time.Now()
	appCfg := s.appConfig()
	if !ok || now.After(entry.resetAt) {
		s.authLimiter[ip] = &enrollRateEntry{count: 1, resetAt: now.Add(appCfg.Runtime.AuthRateLimitWindow)}
		return false
	}
	entry.count++
	if entry.count > appCfg.Runtime.AuthRateLimitMax {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many requests, try again later"})
		return true
	}
	return false
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if s.checkAuthRateLimit(w, r) {
		return
	}

	// Note: login endpoint is exempt from CSRF validation because
	// there is no existing session to protect — the credentials themselves
	// are the authentication factor. Rate limiting prevents brute force.

	var req models.LoginRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	resp, err := s.pa.Auth.Login(req)
	if err != nil {
		log.Printf("[AUTH] Login error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authentication failed"})
		return
	}

	status := http.StatusOK
	if resp.Status == "denied" {
		status = http.StatusUnauthorized
	}

	writeJSON(w, status, resp)
}

func (s *Server) handleVerifyMFA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if s.checkAuthRateLimit(w, r) {
		return
	}

	// CSRF validation for browser-based MFA requests
	if origin := r.Header.Get("Origin"); origin != "" {
		if !validateCSRF(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "CSRF validation failed"})
			return
		}
	}

	var req models.MFAVerifyRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	resp, err := s.pa.Auth.VerifyMFA(req)
	if err != nil {
		log.Printf("[AUTH] MFA verify error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "verification failed"})
		return
	}

	status := http.StatusOK
	if resp.Status == "denied" {
		status = http.StatusUnauthorized
	}

	writeJSON(w, status, resp)
}

// POST /api/auth/mfa-step-up
// Accepts an auth token (MFADone=false) and returns a temporary MFA token
// plus the user's configured MFA methods. Called by the login page when
// the policy engine requires MFA for resource access.
func (s *Server) handleMFAStepUp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if s.checkAuthRateLimit(w, r) {
		return
	}

	if origin := r.Header.Get("Origin"); origin != "" {
		if !validateCSRF(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "CSRF validation failed"})
			return
		}
	}

	var req models.MFAStepUpRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.AuthToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "auth_token is required"})
		return
	}

	// Parse the auth token WITHOUT requiring MFADone=true
	claims, err := s.pa.Auth.ParseToken(req.AuthToken)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, models.MFAStepUpResponse{
			Status:  "denied",
			Message: "Invalid or expired auth token",
		})
		return
	}

	// Look up user to get configured MFA methods
	user, exists := s.pa.Auth.Users.GetUser(claims.UserID)
	if !exists {
		writeJSON(w, http.StatusUnauthorized, models.MFAStepUpResponse{
			Status:  "denied",
			Message: "User not found",
		})
		return
	}

	if !user.MFAEnabled() {
		writeJSON(w, http.StatusBadRequest, models.MFAStepUpResponse{
			Status:  "denied",
			Message: "No MFA methods configured for this user",
		})
		return
	}

	// Issue a temporary MFA token carrying the user's methods
	mfaToken, err := s.pa.Auth.JWT.GenerateMFAToken(user.ID, user.Username, user.Role, user.MFAMethods)
	if err != nil {
		log.Printf("[AUTH] MFA step-up token error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to issue MFA token"})
		return
	}

	log.Printf("[AUTH] MFA step-up: %s — issued MFA token, methods=%v", user.Username, user.MFAMethods)

	writeJSON(w, http.StatusOK, models.MFAStepUpResponse{
		Status:     "mfa_required",
		Message:    "MFA verification required",
		MFAToken:   mfaToken,
		MFAMethods: user.MFAMethods,
	})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if s.checkAuthRateLimit(w, r) {
		return
	}

	var req models.RegisterRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	user, err := s.pa.Auth.Users.Register(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "registration failed", err)
		return
	}

	writeJSON(w, http.StatusCreated, models.APIResponse{
		Success: true,
		Message: "User registered successfully",
		Data: map[string]string{
			"user_id":  user.ID,
			"username": user.Username,
		},
	})
}

func (s *Server) handleEnrollMFA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	userID := r.Header.Get("X-User-ID")
	resp, err := s.pa.Auth.Users.EnrollMFA(userID, s.pa.Cfg.TOTPIssuer)
	if err != nil {
		writeError(w, http.StatusBadRequest, "MFA enrollment failed", err)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleActivateMFA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	userID := r.Header.Get("X-User-ID")

	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if err := s.pa.Auth.Users.ActivateMFA(userID, body.Code); err != nil {
		writeError(w, http.StatusBadRequest, "MFA activation failed", err)
		return
	}

	writeJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Message: "MFA activated successfully",
	})
}
