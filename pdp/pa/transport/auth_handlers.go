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
	ip := clientIPFromRequest(r)
	if ip == "" {
		ip = "unknown"
	}
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
	if user.PasswordChangeRequired {
		challenge, err := s.adminPasswordChanges.create(user, ttl)
		if err != nil {
			log.Printf("[AUTH] Password change challenge error: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "password change setup failed"})
			return
		}
		if s.pa.Audit != nil {
			s.pa.Audit.LogEvent("admin_password_change_required", user.ID, user.Username, r.RemoteAddr, "", "", "Initial password change required", true)
		}
		writeJSON(w, http.StatusOK, models.LoginResponse{
			Status:                 "password_change_required",
			Message:                "Password change required",
			UserID:                 user.ID,
			ChallengeID:            challenge.ID,
			PasswordChangeRequired: true,
		})
		return
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
	response, err := s.adminMFASetupResponse(user, challenge, secret, "Set up MFA to continue", false)
	if err != nil {
		log.Printf("[AUTH] TOTP QR code error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "MFA setup failed"})
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleInitialPasswordChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.checkAuthRateLimit(w, r) {
		return
	}

	var req models.InitialPasswordChangeRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if strings.TrimSpace(req.ChallengeID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password change challenge is required"})
		return
	}
	if req.NewPassword != req.ConfirmPassword {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password confirmation does not match"})
		return
	}

	challenge, found := s.adminPasswordChanges.get(req.ChallengeID)
	if !found {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "password change challenge expired or invalid"})
		return
	}
	user, exists := s.pa.Auth.Users.GetUser(challenge.UserID)
	if !exists || user == nil || user.Disabled || user.Role != "platform_admin" {
		s.adminPasswordChanges.consume(challenge.ID)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user is not available"})
		return
	}
	if !user.PasswordChangeRequired {
		s.adminPasswordChanges.consume(challenge.ID)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password change is not required"})
		return
	}
	if err := s.pa.Auth.Users.CompleteRequiredPasswordChange(user.ID, req.NewPassword); err != nil {
		log.Printf("[AUTH] Initial password change failed for user=%s: %v", user.Username, err)
		if writePasswordPolicyError(w, http.StatusBadRequest, err) {
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	s.adminPasswordChanges.consume(challenge.ID)
	_ = s.pa.Runtime.ResetLoginAttempts(user.Username)
	if s.pa.Audit != nil {
		s.pa.Audit.LogEvent("admin_password_changed", user.ID, user.Username, r.RemoteAddr, "", "", "Initial password changed", true)
	}
	writeJSON(w, http.StatusOK, models.LoginResponse{
		Status:  "password_changed",
		Message: "Password changed. Sign in again with the new password.",
		UserID:  user.ID,
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

func (s *Server) handleAdminSessionRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	sessionID, refreshTokenValue, ok := adminSessionCredentialsFromCookies(r)
	if !ok {
		clearAdminSessionCookies(w)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired session"})
		return
	}
	session, refreshToken, err := s.adminSessions.refresh(sessionID, refreshTokenValue, s.lookupAdminSessionUser)
	if err != nil {
		if errors.Is(err, errAdminSessionNotFound) || errors.Is(err, errAdminSessionExpired) || errors.Is(err, errAdminSessionRefreshMismatch) {
			clearAdminSessionCookies(w)
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
	s.writeAdminSessionResponse(w, http.StatusOK, response)
}

func (s *Server) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	sessionID, refreshToken, hasSessionCookies := adminSessionCredentialsFromCookies(r)

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
	if hasSessionCookies {
		s.adminSessions.revokeWithRefresh(sessionID, refreshToken)
	}
	clearAdminSessionCookies(w)

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
	if user.PasswordChangeRequired {
		s.adminMFA.consume(challenge.ID)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "password change required"})
		return
	}

	var verifyErr error
	var recoveryCodes []string
	if strings.TrimSpace(challenge.PendingTOTPSecret) != "" {
		verifyErr = s.pa.Auth.Users.ActivateTOTPSecret(user.ID, challenge.PendingTOTPSecret, req.Code)
		if verifyErr == nil {
			recoveryCodes, verifyErr = s.pa.Auth.Users.GenerateRecoveryCodes(user.ID)
		}
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
			Status:        "authenticated",
			Message:       "Authentication successful",
			AuthToken:     authToken,
			UserID:        user.ID,
			Purpose:       challenge.Purpose,
			MFARequired:   true,
			RecoveryCodes: recoveryCodes,
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
	response.RecoveryCodes = recoveryCodes
	s.writeAdminSessionResponse(w, http.StatusOK, response)
}

func (s *Server) handleMFARecovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s.checkAuthRateLimit(w, r) {
		return
	}

	var req models.MFARecoveryRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	challenge, found := s.adminMFA.get(req.ChallengeID)
	if !found {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "MFA challenge expired or invalid"})
		return
	}
	if strings.TrimSpace(challenge.PendingTOTPSecret) != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "recovery code cannot be used during MFA setup"})
		return
	}
	user, exists := s.pa.Auth.Users.GetUser(challenge.UserID)
	if !exists || user == nil || user.Disabled {
		s.adminMFA.consume(challenge.ID)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user is not available"})
		return
	}
	if user.PasswordChangeRequired {
		s.adminMFA.consume(challenge.ID)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "password change required"})
		return
	}
	if err := s.pa.Auth.Users.VerifyRecoveryCode(user.ID, req.RecoveryCode); err != nil {
		log.Printf("[AUTH] MFA recovery failed for user=%s: %v", user.Username, err)
		if retry := s.adminMFA.recordFailure(challenge.ID, s.appConfig().MaxLoginAttempts); !retry {
			_ = s.pa.Runtime.RecordFailedLogin(user.Username, s.appConfig().MaxLoginAttempts, s.appConfig().LockoutDuration)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "too many failed recovery attempts"})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid recovery code"})
		return
	}

	secret, err := paauth.GenerateTOTPSecret()
	if err != nil {
		log.Printf("[AUTH] TOTP setup after recovery error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "MFA setup failed"})
		return
	}
	ttl := time.Until(challenge.ExpiresAt)
	setupChallenge, err := s.adminMFA.create(user, secret, ttl, challenge.Purpose)
	if err != nil {
		log.Printf("[AUTH] MFA setup challenge after recovery error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "MFA setup failed"})
		return
	}
	s.adminMFA.consume(challenge.ID)
	if s.pa.Audit != nil {
		s.pa.Audit.LogEvent("admin_recovery_code_used", user.ID, user.Username, r.RemoteAddr, "", "", "MFA recovery code accepted", true)
	}
	response, err := s.adminMFASetupResponse(user, setupChallenge, secret, "Recovery code accepted. Set up MFA to continue.", true)
	if err != nil {
		log.Printf("[AUTH] TOTP QR code after recovery error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "MFA setup failed"})
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) adminMFASetupResponse(user *models.User, challenge *adminMFAChallenge, secret, message string, recoveryUsed bool) (*models.LoginResponse, error) {
	if user == nil || challenge == nil {
		return nil, errors.New("MFA setup response requires user and challenge")
	}
	qrURI := paauth.BuildTOTPURI(secret, s.appConfig().TOTPIssuer, user.Username)
	qrImage, err := paauth.BuildTOTPQRCodeImage(qrURI)
	if err != nil {
		return nil, err
	}
	return &models.LoginResponse{
		Status:       "mfa_setup_required",
		Message:      message,
		UserID:       user.ID,
		Purpose:      challenge.Purpose,
		ChallengeID:  challenge.ID,
		MFARequired:  true,
		MFASetup:     true,
		RecoveryUsed: recoveryUsed,
		Secret:       secret,
		QRCodeURL:    qrURI,
		QRCodeImage:  qrImage,
	}, nil
}

func (s *Server) startAdminSession(user *models.User, message string) (*models.LoginResponse, error) {
	if user == nil {
		return nil, errors.New("admin session requires user")
	}
	if user.PasswordChangeRequired {
		return nil, errors.New("password change required")
	}
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
	if !ok || user == nil || user.Disabled || user.Role != "platform_admin" || user.PasswordChangeRequired {
		return nil, false
	}
	return user, true
}

func (s *Server) authenticatePrimaryLogin(w http.ResponseWriter, r *http.Request, req models.LoginRequest) (*models.User, bool) {
	identifier := req.Identifier()
	sourceIP := clientIPFromRequest(r)
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
			s.pa.Audit.LogEvent("admin_login", "", identifier, sourceIP, "", "", "Default admin/admin credentials rejected", false)
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
			s.pa.Audit.LogEvent("admin_login", "", identifier, sourceIP, "", "", "Account locked until "+until.Format(time.RFC3339), false)
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
			s.pa.Audit.LogEvent("admin_login", "", identifier, sourceIP, "", "", "Invalid credentials", false)
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
		s.pa.Audit.LogEvent("admin_login", user.ID, user.Username, sourceIP, "", "", "Primary authentication completed", true)
	}
	return user, true
}
