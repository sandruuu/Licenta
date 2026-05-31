package transport

import (
	"encoding/json"
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

	var req models.LoginRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	user, ok := s.authenticatePrimaryLogin(w, r, req)
	if !ok {
		return
	}

	if !s.appConfig().AdminMFARequired() {
		s.issueAdminLoginToken(w, r, user)
		return
	}

	ttl := s.appConfig().Runtime.BrowserAuthSessionTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if s.userHasTOTPConfigured(user) {
		challenge, err := s.adminMFA.create(user, "", ttl)
		if err != nil {
			log.Printf("[AUTH] MFA challenge error: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "MFA challenge failed"})
			return
		}
		writeJSON(w, http.StatusOK, models.LoginResponse{
			Status:      "mfa_required",
			Message:     "MFA verification required",
			UserID:      user.ID,
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
	challenge, err := s.adminMFA.create(user, secret, ttl)
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
		ChallengeID: challenge.ID,
		MFARequired: true,
		MFASetup:    true,
		Secret:      secret,
		QRCodeURL:   qrURI,
		QRCodeImage: qrImage,
	})
}

func (s *Server) issueAdminLoginToken(w http.ResponseWriter, r *http.Request, user *models.User) {
	authToken, err := s.pa.Auth.JWT.GenerateAuthToken(user.ID, user.Username, "platform_admin", "", "", true)
	if err != nil {
		log.Printf("[AUTH] JWT issue after password login failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authentication failed"})
		return
	}
	if s.pa.Audit != nil {
		s.pa.Audit.LogEvent("admin_login", user.ID, user.Username, r.RemoteAddr, "", "", "Dashboard password login completed; MFA disabled by configuration", true)
	}
	writeJSON(w, http.StatusOK, models.LoginResponse{
		Status:    "authenticated",
		Message:   "Authentication successful",
		AuthToken: authToken,
		UserID:    user.ID,
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

	if s.hasLocalPlatformAdmin() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "administrator registration is disabled"})
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

func (s *Server) hasLocalPlatformAdmin() bool {
	for _, user := range s.pa.Auth.Users.ListUsers() {
		if user == nil {
			continue
		}
		if strings.TrimSpace(user.PasswordHash) == "" || strings.TrimSpace(user.AuthSource) != "" {
			continue
		}
		if user.Role == "platform_admin" {
			return true
		}
	}
	return false
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
			s.pa.Store.RecordFailedLogin(user.Username, s.appConfig().MaxLoginAttempts, s.appConfig().LockoutDuration)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "too many failed MFA attempts"})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid MFA code"})
		return
	}

	s.adminMFA.consume(challenge.ID)
	s.pa.Store.ResetLoginAttempts(user.Username)
	authToken, err := s.pa.Auth.JWT.GenerateAuthToken(user.ID, user.Username, "platform_admin", "", "", true)
	if err != nil {
		log.Printf("[AUTH] JWT issue after MFA failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authentication failed"})
		return
	}
	if s.pa.Audit != nil {
		s.pa.Audit.LogEvent("admin_mfa_completed", user.ID, user.Username, r.RemoteAddr, "", "", "Dashboard MFA completed", true)
	}
	writeJSON(w, http.StatusOK, models.LoginResponse{
		Status:      "authenticated",
		Message:     "Authentication successful",
		AuthToken:   authToken,
		UserID:      user.ID,
		MFARequired: true,
	})
}

func (s *Server) authenticatePrimaryLogin(w http.ResponseWriter, r *http.Request, req models.LoginRequest) (*models.User, bool) {
	if strings.EqualFold(strings.TrimSpace(req.Username), "admin") && req.Password == "admin" {
		s.pa.Store.RecordFailedLogin(req.Username, s.appConfig().MaxLoginAttempts, s.appConfig().LockoutDuration)
		if s.pa.Audit != nil {
			s.pa.Audit.LogEvent("admin_login", "", req.Username, r.RemoteAddr, "", "", "Default admin/admin credentials rejected", false)
		}
		writeJSON(w, http.StatusUnauthorized, models.LoginResponse{
			Status:  "denied",
			Message: "Default administrator credentials are disabled",
		})
		return nil, false
	}

	if locked, until := s.pa.Store.IsLockedOut(req.Username); locked {
		if s.pa.Audit != nil {
			s.pa.Audit.LogEvent("admin_login", "", req.Username, r.RemoteAddr, "", "", "Account locked until "+until.Format(time.RFC3339), false)
		}
		writeJSON(w, http.StatusUnauthorized, models.LoginResponse{
			Status:  "denied",
			Message: "Account temporarily locked due to too many failed attempts",
		})
		return nil, false
	}
	user, err := s.pa.Auth.Users.Authenticate(req.Username, req.Password)
	if err != nil {
		s.pa.Store.RecordFailedLogin(req.Username, s.appConfig().MaxLoginAttempts, s.appConfig().LockoutDuration)
		if s.pa.Audit != nil {
			s.pa.Audit.LogEvent("admin_login", "", req.Username, r.RemoteAddr, "", "", "Invalid credentials", false)
		}
		writeJSON(w, http.StatusUnauthorized, models.LoginResponse{
			Status:  "denied",
			Message: "Invalid credentials",
		})
		return nil, false
	}
	if user.Role != "platform_admin" {
		s.pa.Store.RecordFailedLogin(req.Username, s.appConfig().MaxLoginAttempts, s.appConfig().LockoutDuration)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "platform administrator access required"})
		return nil, false
	}
	s.pa.Store.ResetLoginAttempts(req.Username)
	if s.pa.Audit != nil {
		s.pa.Audit.LogEvent("admin_login", user.ID, user.Username, r.RemoteAddr, "", "", "Primary authentication completed", true)
	}
	return user, true
}
