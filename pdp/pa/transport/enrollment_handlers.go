package transport

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"pdp/models"
	paenrollment "pdp/pa/enrollment"
)

// ─────────────────────────────────────────────
// Device Enrollment
// ─────────────────────────────────────────────

// checkEnrollRateLimit enforces configured per-IP rate limiting on enrollment endpoints.
// Uses an in-memory fast-path cache backed by persistent SQLite storage so limits survive PDP restarts.
func (s *Server) checkEnrollRateLimit(ip string) bool {
	// In-memory fast path: skip SQLite round-trip for well-behaved clients.
	s.enrollLimiterMu.Lock()
	now := time.Now()
	appCfg := s.appConfig()
	entry, ok := s.enrollLimiter[ip]
	if !ok || now.After(entry.resetAt) {
		s.enrollLimiter[ip] = &enrollRateEntry{count: 1, resetAt: now.Add(appCfg.Runtime.EnrollRateLimitWindow)}
		s.enrollLimiterMu.Unlock()
		// Update persistent counter in background; failure is non-fatal.
		if s.pa != nil && s.pa.Store != nil {
			go func() {
				if allowed, err := s.pa.Store.CheckEnrollRateLimit(ip, appCfg.Runtime.EnrollRateLimitWindow, appCfg.Runtime.EnrollRateLimitMax); err == nil && !allowed {
					log.Printf("[ENROLL] Persistent rate limiter denied IP %s (in-memory passed)", ip)
				}
			}()
		}
		return true
	}
	entry.count++
	if entry.count <= appCfg.Runtime.EnrollRateLimitMax {
		s.enrollLimiterMu.Unlock()
		return true
	}
	s.enrollLimiterMu.Unlock()
	// In-memory says denied. Validate against persistent store as defense-in-depth.
	if s.pa != nil && s.pa.Store != nil {
		allowed, err := s.pa.Store.CheckEnrollRateLimit(ip, appCfg.Runtime.EnrollRateLimitWindow, appCfg.Runtime.EnrollRateLimitMax)
		if err != nil {
			log.Printf("[ENROLL] Persistent rate limit check failed for IP %s: %v", ip, err)
			return false
		}
		return allowed
	}
	return false
}

// canonicalCSRPEM accepts PEM, DER, or base64 DER CSR input and returns a
// normalized PEM CSR after verifying its signature.
func canonicalCSRPEM(input string) (string, error) {
	return paenrollment.CanonicalCSRPEM(input)
}

func parseCSR(input string) (*x509.CertificateRequest, []byte, error) {
	return paenrollment.ParseCSR(input)
}

// computeCSRFingerprint extracts the public key from a CSR and returns its SHA-256 hex fingerprint.
// This prevents clients from spoofing the fingerprint field.
func computeCSRFingerprint(csrPEM string) (string, error) {
	return paenrollment.ComputeCSRFingerprint(csrPEM)
}

func shortFingerprint(value string) string {
	return paenrollment.ShortFingerprint(value)
}

func (s *Server) handleDeviceEnroll(w http.ResponseWriter, r *http.Request) {
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

	result, err := s.pa.Enrollment.SubmitPendingDeviceEnrollment(req)
	if err != nil {
		s.writePendingEnrollmentError(w, req.DeviceID, err)
		return
	}

	switch result.Action {
	case paenrollment.PendingEnrollmentAlreadyPending:
		writeJSON(w, http.StatusOK, models.EnrollmentResponse{
			ID:      result.Enrollment.ID,
			Status:  "pending",
			Message: "Enrollment request already pending admin approval",
		})
	case paenrollment.PendingEnrollmentAlreadyApproved:
		writeJSON(w, http.StatusConflict, models.EnrollmentResponse{
			ID:      result.Enrollment.ID,
			Status:  "approved",
			Message: "Device already has a valid certificate for this component",
		})
	default:
		writeJSON(w, http.StatusAccepted, models.EnrollmentResponse{
			ID:      result.Enrollment.ID,
			Status:  "pending",
			Message: "Enrollment request submitted, awaiting admin approval",
		})
	}
}

func (s *Server) handleEnrollmentStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Only allow lookup by enrollment ID (256-bit secret), not by predictable device_id
	enrollmentID := r.URL.Query().Get("id")
	if enrollmentID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id parameter required"})
		return
	}

	resp, err := s.pa.Enrollment.DeviceEnrollmentStatus(enrollmentID)
	if err != nil {
		if errors.Is(err, paenrollment.ErrInvalidRequest) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id parameter required"})
			return
		}
		if !errors.Is(err, paenrollment.ErrNotFound) {
			log.Printf("[ENROLL] Failed to load enrollment status for %s: %v", enrollmentID, err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load enrollment status"})
			return
		}
		writeJSON(w, http.StatusNotFound, models.EnrollmentResponse{Status: "not_found", Message: "No enrollment found"})
		return
	}

	if resp.Status == "approved" {
		if caPEM, err := s.getCAPEM(); err == nil {
			resp.CAPEM = string(caPEM)
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) writePendingEnrollmentError(w http.ResponseWriter, deviceID string, err error) {
	switch {
	case errors.Is(err, paenrollment.ErrInvalidRequest):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": enrollmentClientMessage(err)})
	case errors.Is(err, paenrollment.ErrInvalidCSR):
		log.Printf("[ENROLL] Invalid CSR from device %s: %v", deviceID, err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid CSR"})
	case errors.Is(err, paenrollment.ErrPendingDifferentKey):
		writeJSON(w, http.StatusForbidden, models.EnrollmentResponse{
			Status:  "rejected",
			Message: "Enrollment already pending with a different device key",
		})
	default:
		log.Printf("[ENROLL] Failed to create pending enrollment for device %s: %v", deviceID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create enrollment request"})
	}
}

func (s *Server) writeBrowserEnrollmentStartError(w http.ResponseWriter, deviceID string, err error) {
	switch {
	case errors.Is(err, paenrollment.ErrInvalidRequest):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": enrollmentClientMessage(err)})
	case errors.Is(err, paenrollment.ErrInvalidCSR):
		log.Printf("[ENROLL] Invalid CSR from device %s: %v", deviceID, err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid CSR"})
	case errors.Is(err, paenrollment.ErrAlreadyEnrolled):
		writeJSON(w, http.StatusConflict, map[string]string{"error": paenrollment.ErrAlreadyEnrolled.Error()})
	default:
		log.Printf("[ENROLL] Failed to start browser enrollment for device %s: %v", deviceID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate session ID"})
	}
}
