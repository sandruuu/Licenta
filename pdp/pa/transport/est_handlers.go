package transport

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"pdp/models"
	"pdp/pa/auth"
	paenrollment "pdp/pa/enrollment"
)

// handleESTCACerts exposes the issuing CA bundle through the standard EST
// discovery path used by endpoint agents before certificate enrollment.
func (s *Server) handleESTCACerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	caPEM, err := s.getCAPEM()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "CA certificate is not available"})
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(caPEM)
}

// handleESTSimpleEnroll performs authenticated EST-style enrollment. It accepts
// a CSR as JSON (csr_pem) or raw PEM/DER/base64 DER and returns the endpoint
// certificate plus CA chain. Authentication is a Cloud JWT bearer token from the
// browser/OIDC login flow; MFA remains conditional at resource access time.
func (s *Server) handleESTSimpleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	claims, err := s.estBearerClaims(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid bearer token"})
		return
	}

	req, err := readESTEnrollmentRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var tokenExpiresAt time.Time
	if claims.ExpiresAt != nil {
		tokenExpiresAt = claims.ExpiresAt.Time
	}
	result, err := s.pa.Enrollment.CompleteESTEnrollment(req, paenrollment.ESTEnrollmentIdentity{
		DeviceID:       claims.DeviceID,
		UserID:         claims.UserID,
		Username:       claims.Username,
		TokenID:        claims.ID,
		TokenExpiresAt: tokenExpiresAt,
	})
	if err != nil {
		s.writeESTEnrollmentError(w, req.DeviceID, err)
		return
	}
	caPEM, err := s.getCAPEM()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "CA certificate is not available"})
		return
	}

	s.pa.Audit.LogEvent("est_enrollment", claims.UserID, claims.Username,
		r.RemoteAddr, "", "", "Endpoint "+result.Enrollment.DeviceID+" enrolled via EST", true)
	log.Printf("[EST] Endpoint certificate ready: device=%s user=%s serial=%s reused=%v",
		result.Enrollment.DeviceID, claims.Username, result.Enrollment.CertSerial, result.Reused)

	writeESTCertificateResponse(w, r, result.Enrollment.ID, result.CertPEM, caPEM, result.Reused)
}

func (s *Server) estBearerClaims(r *http.Request) (*auth.CustomClaims, error) {
	token, err := bearerToken(r)
	if err != nil {
		return nil, err
	}
	claims, err := s.pa.Auth.JWT.ParseEnrollmentToken(token)
	if err != nil {
		return nil, err
	}
	if claims.Nonce != "" && r.Header.Get("X-ZTNA-Enrollment-Nonce") != claims.Nonce {
		return nil, fmt.Errorf("enrollment nonce mismatch")
	}
	return claims, nil
}

func bearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") || strings.TrimSpace(parts[1]) == "" {
		return "", fmt.Errorf("bearer token required")
	}
	return strings.TrimSpace(parts[1]), nil
}

func validateCSREmailIdentity(csr *x509.CertificateRequest, username string) error {
	return paenrollment.ValidateCSREmailIdentity(csr, username)
}

func (s *Server) writeESTEnrollmentError(w http.ResponseWriter, deviceID string, err error) {
	switch {
	case errors.Is(err, paenrollment.ErrInvalidToken), errors.Is(err, paenrollment.ErrTokenAlreadyUsed):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": enrollmentClientMessage(err)})
	case errors.Is(err, paenrollment.ErrInvalidRequest):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": enrollmentClientMessage(err)})
	case errors.Is(err, paenrollment.ErrForbidden):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": enrollmentClientMessage(err)})
	case errors.Is(err, paenrollment.ErrInvalidCSR):
		message := enrollmentClientMessage(err)
		if strings.Contains(message, "CSR common name") || strings.Contains(message, "CSR email") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": message})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid CSR"})
	default:
		log.Printf("[EST] Failed to issue endpoint certificate for device %s: %v", deviceID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to sign certificate"})
	}
}

func (s *Server) handleIssueEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	token, err := bearerToken(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authorization header required"})
		return
	}
	claims, err := s.pa.Auth.JWT.ParseAuthTokenForAudience(token, auth.AgentTokenAudience)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid parent token"})
		return
	}

	var body struct {
		DeviceID string `json:"device_id"`
		Nonce    string `json:"nonce"`
		UserSID  string `json:"user_sid"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil && err != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	issuedToken, err := s.pa.Enrollment.IssueEnrollmentToken(paenrollment.EnrollmentTokenParent{
		TokenID:  claims.ID,
		Purpose:  claims.Purpose,
		UserID:   claims.UserID,
		Username: claims.Username,
		Role:     claims.Role,
		DeviceID: claims.DeviceID,
	}, paenrollment.EnrollmentTokenIssueRequest{
		DeviceID: body.DeviceID,
		Nonce:    body.Nonce,
		UserSID:  body.UserSID,
	})
	if err != nil {
		s.writeEnrollmentTokenIssueError(w, err)
		return
	}

	response := map[string]interface{}{
		"enrollment_token": issuedToken.EnrollmentToken,
		"token_type":       issuedToken.TokenType,
		"expires_in":       issuedToken.ExpiresIn,
		"device_id":        issuedToken.DeviceID,
		"nonce":            issuedToken.Nonce,
	}
	if issuedToken.UserSID != "" {
		response["user_sid"] = issuedToken.UserSID
	}
	if issuedToken.UserEmail != "" {
		response["user_email"] = issuedToken.UserEmail
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) writeEnrollmentTokenIssueError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, paenrollment.ErrInvalidParentToken):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid parent token"})
	case errors.Is(err, paenrollment.ErrTokenRevoked):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "token has been revoked"})
	case errors.Is(err, paenrollment.ErrForbidden):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": enrollmentClientMessage(err)})
	case errors.Is(err, paenrollment.ErrInvalidRequest):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": enrollmentClientMessage(err)})
	case errors.Is(err, paenrollment.ErrNonceGeneration):
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate nonce"})
	case errors.Is(err, paenrollment.ErrTokenIssue):
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate enrollment token"})
	default:
		log.Printf("[ENROLL] Failed to issue enrollment token: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate enrollment token"})
	}
}

func readESTEnrollmentRequest(r *http.Request) (models.EnrollmentRequest, error) {
	var req models.EnrollmentRequest
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(contentType, "application/json") {
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			return req, fmt.Errorf("invalid JSON request body")
		}
	} else {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			return req, fmt.Errorf("read CSR body: %w", err)
		}
		req.CSRPEM = string(body)
		req.DeviceID = strings.TrimSpace(r.Header.Get("X-Device-ID"))
		req.Hostname = strings.TrimSpace(r.Header.Get("X-Hostname"))
		req.Component = strings.TrimSpace(r.Header.Get("X-ZTNA-Component"))
	}
	req.Component = normalizeEnrollmentComponent(req.Component)
	if strings.TrimSpace(req.CSRPEM) == "" {
		return req, fmt.Errorf("csr_pem is required")
	}
	return req, nil
}

func writeESTCertificateResponse(w http.ResponseWriter, r *http.Request, id string, certPEM, caPEM []byte, reused bool) {
	accept := strings.ToLower(r.Header.Get("Accept"))
	if strings.Contains(accept, "application/json") {
		writeJSON(w, http.StatusOK, models.EnrollmentResponse{
			ID:      id,
			Status:  "approved",
			CertPEM: string(certPEM),
			CAPEM:   string(caPEM),
			Message: fmt.Sprintf("Endpoint certificate ready (reused=%v)", reused),
		})
		return
	}

	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.Header().Set("X-Enrollment-ID", id)
	w.Header().Set("X-Certificate-Reused", strconv.FormatBool(reused))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(certPEM)
	if len(caPEM) > 0 {
		if len(certPEM) > 0 && certPEM[len(certPEM)-1] != '\n' {
			_, _ = w.Write([]byte("\n"))
		}
		_, _ = w.Write(caPEM)
	}
}
