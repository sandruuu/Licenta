package transport

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"pdp/models"
	"pdp/util"
)

// ─────────────────────────────────────────────
// Browser Auth Flow Handlers (Duo-like)
// ─────────────────────────────────────────────

// handleWebLoginPage serves the React access login page with a CSRF token cookie.
func (s *Server) handleWebLoginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Generate and set CSRF token as a cookie (double-submit cookie pattern)
	csrfToken := generateCSRFToken()
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Path:     "/",
		HttpOnly: false, // Must be readable by JavaScript for double-submit
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   s.appConfig().Runtime.CSRFCookieMaxAgeSeconds,
	})

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	s.serveDashboardIndex(w, r)
}

// generateCSRFToken creates a cryptographically random CSRF token
func generateCSRFToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// validateCSRF checks the double-submit cookie CSRF token.
// The token from the X-CSRF-Token header must match the csrf_token cookie.
func validateCSRF(r *http.Request) bool {
	cookie, err := r.Cookie("csrf_token")
	if err != nil || cookie.Value == "" {
		return false
	}
	headerToken := r.Header.Get("X-CSRF-Token")
	if headerToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(headerToken)) == 1
}

// handleStartSession creates a pending browser auth session (called by connect-app)
func (s *Server) handleStartSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req models.StartAuthSessionRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	sessionID, err := util.GenerateID("auth")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate session ID"})
		return
	}

	session := &models.PendingAuthSession{
		ID:           sessionID,
		DeviceID:     req.DeviceID,
		Hostname:     req.Hostname,
		Status:       "pending",
		DeviceHealth: req.DeviceHealth,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(s.appConfig().Runtime.BrowserAuthSessionTTL),
	}

	s.pa.Store.SavePendingAuth(session)

	// Store device health if provided
	if req.DeviceHealth != nil && req.DeviceID != "" {
		req.DeviceHealth.DeviceID = req.DeviceID
		s.pa.ReportDeviceHealth(req.DeviceHealth)
	}

	// Build auth URL - the browser page URL with session parameter
	// Use the request host to build the URL
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	authURL := fmt.Sprintf("%s://%s/auth/login?session=%s", scheme, r.Host, sessionID)

	log.Printf("[API] Browser auth session created: %s (device=%s, host=%s)", sessionID, req.DeviceID, req.Hostname)

	writeJSON(w, http.StatusOK, models.StartAuthSessionResponse{
		SessionID: sessionID,
		AuthURL:   authURL,
		ExpiresIn: int(s.appConfig().Runtime.BrowserAuthSessionTTL.Seconds()),
	})
}

// handleSessionStatus returns the current status of a pending auth session (polled by connect-app)
func (s *Server) handleSessionStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session parameter required"})
		return
	}

	session, ok := s.pa.Store.GetPendingAuth(sessionID)
	if !ok {
		writeJSON(w, http.StatusNotFound, models.AuthSessionStatusResponse{
			Status:  "expired",
			Message: "Session not found or expired",
		})
		return
	}

	// Check expiration
	if time.Now().After(session.ExpiresAt) {
		s.pa.Store.DeletePendingAuth(sessionID)
		writeJSON(w, http.StatusOK, models.AuthSessionStatusResponse{
			Status:  "expired",
			Message: "Session expired",
		})
		return
	}

	resp := models.AuthSessionStatusResponse{
		Status:  session.Status,
		Message: "Waiting for user authentication",
	}

	if session.Status == "authenticated" {
		resp.AuthToken = session.AuthToken
		resp.Message = "Authentication successful"
		// Clean up the session after token is retrieved
		s.pa.Store.DeletePendingAuth(sessionID)
	} else if session.Status == "denied" {
		resp.Message = "Access denied by security policy"
		s.pa.Store.DeletePendingAuth(sessionID)
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleSessionInfo returns session info including device health (for the browser login page)
func (s *Server) handleSessionInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session parameter required"})
		return
	}

	session, ok := s.pa.Store.GetPendingAuth(sessionID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"session_id":    session.ID,
		"device_id":     session.DeviceID,
		"hostname":      session.Hostname,
		"device_health": session.DeviceHealth,
		"status":        session.Status,
	})
}

// handleCompleteSession is called by the browser after successful login.
// It validates the auth token, evaluates policy, and marks the session as authenticated or denied.
func (s *Server) handleCompleteSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req struct {
		SessionID string `json:"session_id"`
		AuthToken string `json:"auth_token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	session, ok := s.pa.Store.GetPendingAuth(req.SessionID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found or expired"})
		return
	}

	// Validate the auth token
	claims, err := s.pa.Auth.ValidateToken(req.AuthToken)
	if err != nil {
		session.Status = "denied"
		s.pa.Store.SavePendingAuth(session)
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"success":  false,
			"decision": "denied",
			"message":  "Invalid authentication token",
		})
		return
	}

	// Build an access request for policy evaluation
	accessReq := models.AccessRequest{
		UserID:    claims.UserID,
		Username:  claims.Username,
		DeviceID:  session.DeviceID,
		SourceIP:  r.RemoteAddr,
		Resource:  "ztna-access", // general access
		Protocol:  "https",
		AuthToken: req.AuthToken,
	}

	// Load device health from session snapshot or store
	if session.DeviceHealth != nil {
		accessReq.DeviceHealth = session.DeviceHealth
	} else if session.DeviceID != "" {
		if health, ok := s.pa.Store.GetDeviceHealth(session.DeviceID); ok {
			accessReq.DeviceHealth = health
		}
	}

	// Health gate: require device-health-app to be running and reporting
	if accessReq.DeviceHealth == nil && session.DeviceID != "" {
		log.Printf("[API] Session denied: device_id=%s has no health data (HDA not running)", session.DeviceID)
		session.Status = "denied"
		s.pa.Store.SavePendingAuth(session)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success":  false,
			"decision": "denied",
			"message":  "Device Health App is not running or has not reported device status. Start Device Health App and try again.",
		})
		return
	}

	// Evaluate policy
	decision := s.pa.EvaluateAccess(accessReq)

	log.Printf("[API] Session complete: user=%s decision=%s risk=%d",
		claims.Username, decision.Decision, decision.RiskScore)

	switch decision.Decision {
	case "allow":
		session.Status = "authenticated"
		session.AuthToken = req.AuthToken
		session.UserID = claims.UserID
		session.Username = claims.Username
		s.pa.Store.SavePendingAuth(session)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success":    true,
			"decision":   "allow",
			"message":    "Access granted",
			"risk_score": decision.RiskScore,
		})

	case "mfa_required":
		// If user already completed MFA (has MFADone in token), allow anyway
		if claims.MFADone {
			session.Status = "authenticated"
			session.AuthToken = req.AuthToken
			session.UserID = claims.UserID
			session.Username = claims.Username
			s.pa.Store.SavePendingAuth(session)
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"success":    true,
				"decision":   "allow",
				"message":    "Access granted (MFA verified)",
				"risk_score": decision.RiskScore,
			})
		} else {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"success":  false,
				"decision": "mfa_required",
				"message":  decision.Reason,
			})
		}

	default: // "deny", "restrict"
		session.Status = "denied"
		s.pa.Store.SavePendingAuth(session)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success":  false,
			"decision": decision.Decision,
			"message":  decision.Reason,
		})
	}
}
