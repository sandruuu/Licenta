package transport

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"pdp/models"
	paenrollment "pdp/pa/enrollment"
)

// ─────────────────────────────────────────────
// OIDC-Based Auto-Enrollment (browser flow)
// ─────────────────────────────────────────────

// handleEnrollStartSession creates a pending browser enrollment session (called by connect-app).
// The connect-app opens the returned auth_url in the user's browser for OIDC login.
func (s *Server) handleEnrollStartSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Per-IP rate limiting
	clientIP := strings.SplitN(r.RemoteAddr, ":", 2)[0]
	if !s.checkEnrollRateLimit(clientIP) {
		log.Printf("[ENROLL] Rate limit exceeded for IP %s", clientIP)
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded, try again later"})
		return
	}

	var req models.EnrollmentRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	session, err := s.pa.Enrollment.StartBrowserEnrollSession(req)
	if err != nil {
		s.writeBrowserEnrollmentStartError(w, req.DeviceID, err)
		return
	}

	// Build auth URL — same login page, with enroll_session parameter
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	authURL := fmt.Sprintf("%s://%s/auth/login?enroll_session=%s", scheme, r.Host, session.ID)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"session_id": session.ID,
		"auth_url":   authURL,
		"expires_in": int(s.appConfig().Enrollment.BrowserSessionTTL.Seconds()),
	})
}

// handleEnrollCompleteSession is called by the browser after the user logs in.
// It validates the auth token, signs the CSR, and stores the enrollment.
func (s *Server) handleEnrollCompleteSession(w http.ResponseWriter, r *http.Request) {
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

	if _, err := s.pa.Enrollment.ActiveBrowserEnrollSession(req.SessionID); err != nil {
		writeEnrollSessionLifecycleError(w, err)
		return
	}

	// Validate the auth token. Enrollment binds device identity to a logged-in
	// user, while resource-access MFA remains enforced later by policy.
	claims, err := s.pa.Auth.ParseToken(req.AuthToken)
	if err != nil {
		if _, denyErr := s.pa.Enrollment.DenyBrowserEnrollSession(req.SessionID); denyErr != nil {
			log.Printf("[ENROLL] Failed to mark browser enrollment session denied: session=%s err=%v", req.SessionID, denyErr)
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid authentication token"})
		return
	}

	var caPEM string
	if loadedCAPEM, err := s.getCAPEM(); err == nil {
		caPEM = string(loadedCAPEM)
	}

	completion, err := s.pa.Enrollment.CompleteBrowserEnrollSession(req.SessionID, req.AuthToken, claims.UserID, claims.Username, caPEM)
	if err != nil {
		if errors.Is(err, paenrollment.ErrNotFound) || errors.Is(err, paenrollment.ErrExpiredSession) || errors.Is(err, paenrollment.ErrInvalidRequest) {
			writeEnrollSessionLifecycleError(w, err)
			return
		}
		log.Printf("[ENROLL] Failed to complete browser enrollment session %s: %v", req.SessionID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to sign certificate"})
		return
	}

	s.pa.Audit.LogEvent("enrollment_approved", "", claims.Username,
		r.RemoteAddr, "", "", "Device "+completion.Session.DeviceID+" enrolled via OIDC", true)

	log.Printf("[ENROLL] Endpoint certificate ready via OIDC: device=%s user=%s serial=%s reused=%v",
		completion.Session.DeviceID, claims.Username, completion.Enrollment.CertSerial, completion.Reused)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Device enrolled successfully",
	})
}

// handleEnrollSessionStatus returns the enrollment session status (polled by connect-app).
func (s *Server) handleEnrollSessionStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session parameter required"})
		return
	}

	status, err := s.pa.Enrollment.BrowserEnrollSessionStatus(sessionID)
	if err != nil {
		if errors.Is(err, paenrollment.ErrInvalidRequest) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session parameter required"})
			return
		}
		if !errors.Is(err, paenrollment.ErrNotFound) {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load enrollment session"})
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"status":  "expired",
			"message": "Session not found or expired",
		})
		return
	}

	resp := map[string]interface{}{
		"status": status.Status,
	}

	if status.Status == "authenticated" {
		resp["cert_pem"] = status.CertPEM
		resp["ca_pem"] = status.CAPEM
	}
	if status.Message != "" {
		resp["message"] = status.Message
	}

	writeJSON(w, http.StatusOK, resp)
}

func writeEnrollSessionLifecycleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, paenrollment.ErrExpiredSession):
		writeJSON(w, http.StatusGone, map[string]string{"error": "enrollment session expired"})
	case errors.Is(err, paenrollment.ErrInvalidRequest):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session_id required"})
	case errors.Is(err, paenrollment.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "enrollment session not found or expired"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load enrollment session"})
	}
}
