package transport

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"pdp/models"
	paauth "pdp/pa/auth"
)

// checkAuthRateLimit enforces per-IP rate limiting on authentication endpoints.
// Returns true if the request should be rejected (rate limit exceeded).
func (s *Server) checkAuthRateLimit(w http.ResponseWriter, r *http.Request) bool {
	ip, _, _ := strings.Cut(r.RemoteAddr, ":")
	appCfg := s.appConfig()
	if s.pa == nil || s.pa.Runtime == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "rate limiter unavailable"})
		return true
	}
	allowed, err := s.pa.Runtime.Allow("auth", ip, appCfg.Runtime.AuthRateLimitWindow, appCfg.Runtime.AuthRateLimitMax)
	if err != nil {
		log.Printf("[AUTH] Redis rate limit check failed for IP %s: %v", ip, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "rate limiter unavailable"})
		return true
	}
	if allowed {
		return false
	}
	writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many requests, try again later"})
	return true
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if s.checkAuthRateLimit(w, r) {
		return
	}

	var req models.LoginRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	purpose, validPurpose := adminLoginPurpose(req.Purpose)
	if !validPurpose {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid login purpose"})
		return
	}

	user, ok := s.authenticatePrimaryLogin(w, r, req)
	if !ok {
		return
	}

	ttl := s.appConfig().Runtime.BrowserAuthSessionTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if s.userHasTOTPConfigured(user) {
		challenge, err := s.adminMFA.create(user, "", ttl, purpose)
		if err != nil {
			log.Printf("[AUTH] MFA challenge error: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "MFA challenge failed"})
			return
		}
		writeJSON(w, http.StatusOK, models.LoginResponse{
			Status:      "mfa_required",
			Message:     "MFA verification required",
			UserID:      user.ID,
			Purpose:     purpose,
			ChallengeID: challenge.ID,
			MFARequired: true,
		})
		return
	}

	secret, err := paauth.GenerateTOTPSecret()
	if err != nil {
		log.Printf("[AUTH] TOTP setup error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "MFA setup failed"})
		return
	}
	challenge, err := s.adminMFA.create(user, secret, ttl, purpose)
	if err != nil {
		log.Printf("[AUTH] MFA setup challenge error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "MFA setup failed"})
		return
	}
	qrURI := paauth.BuildTOTPURI(secret, s.appConfig().TOTPIssuer, user.Username)
	qrImage, err := paauth.BuildTOTPQRCodeImage(qrURI)
	if err != nil {
		log.Printf("[AUTH] TOTP QR code error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "MFA setup failed"})
		return
	}
	writeJSON(w, http.StatusOK, models.LoginResponse{
		Status:      "mfa_setup_required",
		Message:     "Set up MFA to continue",
		UserID:      user.ID,
		Purpose:     purpose,
		ChallengeID: challenge.ID,
		MFARequired: true,
		MFASetup:    true,
		Secret:      secret,
		QRCodeURL:   qrURI,
		QRCodeImage: qrImage,
	})
}

func adminLoginPurpose(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "dashboard":
		return "", true
	case paauth.PasskeyEnrollmentPurpose:
		return paauth.PasskeyEnrollmentPurpose, true
	default:
		return "", false
	}
}

func (s *Server) handleAdminSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	claims, ok := adminClaimsFromContext(r)
	if !ok || claims == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "admin session claims unavailable"})
		return
	}
	user, exists := s.pa.Auth.Users.GetUser(claims.UserID)
	if !exists || user == nil || user.Disabled || user.Role != "platform_admin" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user is not available"})
		return
	}
	session, _ := adminSessionFromContext(r)
	expiresAt := time.Time{}
	if claims.ExpiresAt != nil {
		expiresAt = claims.ExpiresAt.Time.UTC()
	}
	expiresIn := int64(0)
	expiresAtValue := ""
	if !expiresAt.IsZero() {
		expiresAtValue = expiresAt.Format(time.RFC3339)
		expiresIn = int64(time.Until(expiresAt).Seconds())
		if expiresIn < 0 {
			expiresIn = 0
		}
	}

	writeJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"status":     "authenticated",
			"user_id":    user.ID,
			"username":   user.Username,
			"role":       user.Role,
			"session_id": claims.SessionID,
			"expires_at": expiresAtValue,
			"expires_in": expiresIn,
			"idle_expires_at": func() string {
				if session == nil || session.IdleExpiresAt.IsZero() {
					return ""
				}
				return session.IdleExpiresAt.UTC().Format(time.RFC3339)
			}(),
			"absolute_expires_at": func() string {
				if session == nil || session.AbsoluteExpiresAt.IsZero() {
					return ""
				}
				return session.AbsoluteExpiresAt.UTC().Format(time.RFC3339)
			}(),
		},
	})
}

type adminSessionRefreshRequest struct {
	SessionID    string `json:"session_id"`
	RefreshToken string `json:"refresh_token"`
}

func (s *Server) handleAdminSessionRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.checkAuthRateLimit(w, r) {
		return
	}
	var req adminSessionRefreshRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	session, refreshToken, err := s.adminSessions.refresh(req.SessionID, req.RefreshToken, s.lookupAdminSessionUser)
	if err != nil {
		if errors.Is(err, errAdminSessionNotFound) || errors.Is(err, errAdminSessionExpired) || errors.Is(err, errAdminSessionRefreshMismatch) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired session"})
			return
		}
		log.Printf("[AUTH] Admin session refresh failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session refresh failed"})
		return
	}
	user, ok := s.lookupAdminSessionUser(session.UserID)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user is not available"})
		return
	}
	response, err := s.adminSessionLoginResponse(user, session, refreshToken, "Session refreshed")
	if err != nil {
		log.Printf("[AUTH] Admin session token issue failed: user=%s err=%v", session.UserID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session refresh failed"})
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req adminSessionRefreshRequest
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req)

	if token, err := bearerToken(r); err == nil {
		if claims, err := s.pa.Auth.ValidateToken(token); err == nil && claims != nil {
			if strings.TrimSpace(claims.SessionID) != "" {
				s.adminSessions.revoke(claims.SessionID)
			}
			if claims.ID != "" && claims.ExpiresAt != nil {
				s.pa.Store.RevokeToken(claims.ID, claims.ExpiresAt.Time)
			}
		}
	}
	if strings.TrimSpace(req.SessionID) != "" && strings.TrimSpace(req.RefreshToken) != "" {
		s.adminSessions.revokeWithRefresh(req.SessionID, req.RefreshToken)
	}

	writeJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Data:    map[string]bool{"revoked": true},
	})
}

func (s *Server) handleMFAVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.checkAuthRateLimit(w, r) {
		return
	}

	var req models.MFAVerifyRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	challenge, found := s.adminMFA.get(req.ChallengeID)
	if !found {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "MFA challenge expired or invalid"})
		return
	}
	user, exists := s.pa.Auth.Users.GetUser(challenge.UserID)
	if !exists || user == nil || user.Disabled {
		s.adminMFA.consume(challenge.ID)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user is not available"})
		return
	}

	var verifyErr error
	if strings.TrimSpace(challenge.PendingTOTPSecret) != "" {
		verifyErr = s.pa.Auth.Users.ActivateTOTPSecret(user.ID, challenge.PendingTOTPSecret, req.Code)
	} else {
		verifyErr = s.pa.Auth.Users.VerifyMFA(user.ID, req.Code)
	}
	if verifyErr != nil {
		log.Printf("[AUTH] MFA verification failed for user=%s: %v", user.Username, verifyErr)
		if retry := s.adminMFA.recordFailure(challenge.ID, s.appConfig().MaxLoginAttempts); !retry {
			_ = s.pa.Runtime.RecordFailedLogin(user.Username, s.appConfig().MaxLoginAttempts, s.appConfig().LockoutDuration)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "too many failed MFA attempts"})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid MFA code"})
		return
	}

	s.adminMFA.consume(challenge.ID)
	_ = s.pa.Runtime.ResetLoginAttempts(user.Username)
	if s.pa.Audit != nil {
		details := "Dashboard MFA completed"
		if challenge.Purpose == paauth.PasskeyEnrollmentPurpose {
			details = "Passkey enrollment MFA completed"
		}
		s.pa.Audit.LogEvent("admin_mfa_completed", user.ID, user.Username, r.RemoteAddr, "", "", details, true)
	}
	if challenge.Purpose == paauth.PasskeyEnrollmentPurpose {
		authToken, err := s.pa.Auth.JWT.GenerateAuthTokenWithPurpose(user.ID, user.Username, "platform_admin", "", "", true, challenge.Purpose)
		if err != nil {
			log.Printf("[AUTH] JWT issue after MFA failed: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authentication failed"})
			return
		}
		writeJSON(w, http.StatusOK, models.LoginResponse{
			Status:      "authenticated",
			Message:     "Authentication successful",
			AuthToken:   authToken,
			UserID:      user.ID,
			Purpose:     challenge.Purpose,
			MFARequired: true,
		})
		return
	}
	response, err := s.startAdminSession(user, "Authentication successful")
	if err != nil {
		log.Printf("[AUTH] Admin session start after MFA failed: user=%s err=%v", user.ID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authentication failed"})
		return
	}
	response.MFARequired = true
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) startAdminSession(user *models.User, message string) (*models.LoginResponse, error) {
	session, refreshToken, err := s.adminSessions.create(user)
	if err != nil {
		return nil, err
	}
	return s.adminSessionLoginResponse(user, session, refreshToken, message)
}

func (s *Server) adminSessionLoginResponse(user *models.User, session *adminSessionRecord, refreshToken, message string) (*models.LoginResponse, error) {
	if user == nil || session == nil {
		return nil, errors.New("admin session response requires user and session")
	}
	ttl := s.adminSessions.accessTokenTTL(session)
	if ttl <= 0 {
		return nil, errAdminSessionExpired
	}
	authToken, err := s.pa.Auth.JWT.GenerateAuthTokenWithSession(user.ID, user.Username, user.Role, "", "", true, "", session.ID, ttl)
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().UTC().Add(ttl)
	return &models.LoginResponse{
		Status:           "authenticated",
		Message:          message,
		AuthToken:        authToken,
		RefreshToken:     refreshToken,
		SessionID:        session.ID,
		ExpiresAt:        expiresAt.Format(time.RFC3339),
		ExpiresIn:        int64(ttl.Seconds()),
		RefreshExpiresAt: minTime(session.IdleExpiresAt, session.AbsoluteExpiresAt).UTC().Format(time.RFC3339),
		UserID:           user.ID,
	}, nil
}

func (s *Server) lookupAdminSessionUser(userID string) (*models.User, bool) {
	user, ok := s.pa.Auth.Users.GetUser(strings.TrimSpace(userID))
	if !ok || user == nil || user.Disabled || user.Role != "platform_admin" {
		return nil, false
	}
	return user, true
}

func (s *Server) authenticatePrimaryLogin(w http.ResponseWriter, r *http.Request, req models.LoginRequest) (*models.User, bool) {
	identifier := req.Identifier()
	if identifier == "" {
		writeJSON(w, http.StatusBadRequest, models.LoginResponse{
			Status:  "denied",
			Message: "Email is required",
		})
		return nil, false
	}

	if strings.EqualFold(identifier, "admin") && req.Password == "admin" {
		_ = s.pa.Runtime.RecordFailedLogin(identifier, s.appConfig().MaxLoginAttempts, s.appConfig().LockoutDuration)
		if s.pa.Audit != nil {
			s.pa.Audit.LogEvent("admin_login", "", identifier, r.RemoteAddr, "", "", "Default admin/admin credentials rejected", false)
		}
		writeJSON(w, http.StatusUnauthorized, models.LoginResponse{
			Status:  "denied",
			Message: "Default administrator credentials are disabled",
		})
		return nil, false
	}

	locked, until, err := s.pa.Runtime.IsLockedOut(identifier)
	if err != nil {
		log.Printf("[AUTH] Redis lockout check failed for %s: %v", identifier, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authentication state unavailable"})
		return nil, false
	}
	if locked {
		if s.pa.Audit != nil {
			s.pa.Audit.LogEvent("admin_login", "", identifier, r.RemoteAddr, "", "", "Account locked until "+until.Format(time.RFC3339), false)
		}
		writeJSON(w, http.StatusUnauthorized, models.LoginResponse{
			Status:  "denied",
			Message: "Account temporarily locked due to too many failed attempts",
		})
		return nil, false
	}
	user, err := s.pa.Auth.Users.AuthenticateByEmail(identifier, req.Password)
	if err != nil {
		_ = s.pa.Runtime.RecordFailedLogin(identifier, s.appConfig().MaxLoginAttempts, s.appConfig().LockoutDuration)
		if s.pa.Audit != nil {
			s.pa.Audit.LogEvent("admin_login", "", identifier, r.RemoteAddr, "", "", "Invalid credentials", false)
		}
		writeJSON(w, http.StatusUnauthorized, models.LoginResponse{
			Status:  "denied",
			Message: "Invalid credentials",
		})
		return nil, false
	}
	if user.Role != "platform_admin" {
		_ = s.pa.Runtime.RecordFailedLogin(identifier, s.appConfig().MaxLoginAttempts, s.appConfig().LockoutDuration)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "platform administrator access required"})
		return nil, false
	}
	_ = s.pa.Runtime.ResetLoginAttempts(identifier)
	if s.pa.Audit != nil {
		s.pa.Audit.LogEvent("admin_login", user.ID, user.Username, r.RemoteAddr, "", "", "Primary authentication completed", true)
	}
	return user, true
}
