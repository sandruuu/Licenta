package auth

import (
	"context"
	"crypto/ecdsa"
	"log"
	"strings"
	"time"

	"pdp/config"
	"pdp/mfa"
	"pdp/models"
	"pdp/pki"
	"pdp/store"
	"pdp/util"
)

// Service coordinates identity and authentication services owned by the PA.
// It combines UserManager (user CRUD + password auth), JWTManager (token issuance),
// TOTP-based MFA, and OIDC authorization into a unified authentication flow.
type Service struct {
	Users      *UserManager
	JWT        *JWTManager
	OIDC       *OIDCManager
	WebAuthn   *mfa.WebAuthnProvider // nil if WebAuthn not configured
	Federation *FederationProvider
	Store      *store.Store
	Cfg        *config.Config
}

// New creates a new authentication service.
func New(cfg *config.Config, s *store.Store) *Service {
	if cfg == nil {
		log.Fatal("[AUTH] PDP config is required")
	}
	cfg.ApplyDefaults()

	jwtKey, err := loadJWTSigningKey(cfg)
	if err != nil {
		log.Fatalf("[AUTH] Failed to load JWT signing key: %v", err)
	}

	jwtMgr, err := NewJWTManager(jwtKey, cfg.JWTExpiry, cfg.MFATokenExpiry, cfg.Runtime.OIDCEnrollmentTokenTTL)
	if err != nil {
		log.Fatalf("[AUTH] Failed to initialize JWT manager: %v", err)
	}
	log.Printf("[AUTH] JWT signing initialized (ES256, kid=%s)", jwtMgr.keyID)

	return &Service{
		Users:      NewUserManager(s),
		JWT:        jwtMgr,
		OIDC:       NewOIDCManager(cfg.Runtime.OIDCAuthorizeSessionTTL, cfg.Runtime.OIDCAuthCodeTTL, cfg.Runtime.OIDCRefreshTokenTTL, cfg.Runtime.OIDCCleanupInterval),
		WebAuthn:   mfa.NewWebAuthnProvider(cfg),
		Federation: NewFederationProvider(cfg.Public.OIDCDefaultScopes, cfg.Public.OIDCDefaultClaimMapping, cfg.Runtime.FederationCacheTTL, cfg.Runtime.FederationHTTPTimeout),
		Store:      s,
		Cfg:        cfg,
	}
}

func loadJWTSigningKey(cfg *config.Config) (*ecdsa.PrivateKey, error) {
	if strings.TrimSpace(cfg.PKIURL) == "" || strings.TrimSpace(cfg.PKIToken) == "" {
		log.Printf("[AUTH] Vault Transit not configured; using in-memory JWT signing key")
		return GenerateJWTSigningKey()
	}

	vaultCfg := pki.VaultConfig{
		URL:            cfg.PKIURL,
		Token:          cfg.PKIToken,
		PKIPath:        cfg.PKIPath,
		TransitKeyName: cfg.JWTTransitKey,
		CAFile:         cfg.PKICAFile,
		ServerName:     cfg.PKIServerName,
		Timeout:        cfg.PKITimeout,
	}

	key, err := pki.RestoreOrCreateNamedKey(context.Background(), vaultCfg, cfg.JWTKeyEncryptedPath, "JWT signing")
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Login handles primary authentication (username + password).
// Always returns an auth token with MFADone=false on success.
// MFA is never enforced at login — it is triggered later by the policy engine
// at resource access time (conditional access / step-up authentication).
func (svc *Service) Login(req models.LoginRequest) (*models.LoginResponse, error) {
	// Check lockout
	if locked, until := svc.Store.IsLockedOut(req.Username); locked {
		svc.audit("login", req.Username, "", "", false,
			"Account locked until "+until.Format(time.RFC3339))
		return &models.LoginResponse{
			Status:  "denied",
			Message: "Account temporarily locked due to too many failed attempts",
		}, nil
	}

	// Authenticate with username + password
	user, err := svc.Users.Authenticate(req.Username, req.Password)
	if err != nil {
		// Record failed attempt
		svc.Store.RecordFailedLogin(req.Username, svc.Cfg.MaxLoginAttempts, svc.Cfg.LockoutDuration)
		svc.audit("login", req.Username, "", "", false, "Invalid credentials")
		return &models.LoginResponse{
			Status:  "denied",
			Message: "Invalid credentials",
		}, nil
	}

	// Reset failed attempts on successful password verification
	svc.Store.ResetLoginAttempts(req.Username)

	// Issue auth token with MFADone=false — MFA is handled at access time
	authToken, err := svc.JWT.GenerateAuthToken(user.ID, user.Username, user.Role, "", "", false)
	if err != nil {
		return nil, err
	}

	svc.audit("login", user.Username, user.ID, "", true, "Authenticated (MFA deferred to access time)")
	log.Printf("[AUTH] Login: %s — authenticated (MFADone=false)", user.Username)

	return &models.LoginResponse{
		Status:     "authenticated",
		Message:    "Authentication successful",
		AuthToken:  authToken,
		UserID:     user.ID,
		MFAMethods: user.MFAMethods,
	}, nil
}

// VerifyMFA handles the second authentication factor.
// It dispatches to the correct MFA method based on req.Method:
//   - "totp" (default): TOTP verification
//   - "webauthn": WebAuthn/passkey challenge — not yet implemented
func (svc *Service) VerifyMFA(req models.MFAVerifyRequest) (*models.MFAVerifyResponse, error) {
	// Validate the temporary MFA token
	claims, err := svc.JWT.ValidateMFAToken(req.MFAToken)
	if err != nil {
		svc.audit("mfa_verify", "", "", "", false, "Invalid MFA token: "+err.Error())
		return &models.MFAVerifyResponse{
			Status:  "denied",
			Message: "Invalid or expired MFA token. Please login again.",
		}, nil
	}

	// Default to TOTP for backward compatibility
	method := req.Method
	if method == "" {
		method = "totp"
	}

	// Verify the user has this method configured
	user, exists := svc.Users.GetUser(claims.UserID)
	if !exists {
		return &models.MFAVerifyResponse{
			Status:  "denied",
			Message: "User not found",
		}, nil
	}

	if !containsMFAMethod(claims.MFAMethods, method) {
		svc.audit("mfa_verify", claims.Username, claims.UserID, "", false, "Method not configured: "+method)
		return &models.MFAVerifyResponse{
			Status:  "denied",
			Message: "MFA method not configured for this user",
		}, nil
	}

	// Dispatch to the correct MFA verifier
	switch method {
	case "totp":
		if err := svc.Users.VerifyMFA(claims.UserID, req.TOTPCode); err != nil {
			svc.audit("mfa_verify", claims.Username, claims.UserID, "", false, "Invalid TOTP code")
			return &models.MFAVerifyResponse{
				Status:  "denied",
				Message: "Invalid verification code",
			}, nil
		}
	case "webauthn":
		// WebAuthn uses a challenge-response flow via dedicated endpoints:
		//   POST /api/mfa/webauthn/authenticate/begin  → returns challenge options
		//   POST /api/mfa/webauthn/authenticate/finish  → verifies response, returns auth token
		// The generic VerifyMFA endpoint is not used for WebAuthn.
		return &models.MFAVerifyResponse{
			Status:  "denied",
			Message: "WebAuthn uses the /api/mfa/webauthn/authenticate/* endpoints",
		}, nil
	default:
		return &models.MFAVerifyResponse{
			Status:  "denied",
			Message: "Unsupported MFA method: " + method,
		}, nil
	}

	// Issue full auth token with MFA completed
	authToken, err := svc.JWT.GenerateAuthToken(user.ID, user.Username, user.Role, "", "", true)
	if err != nil {
		return nil, err
	}

	svc.audit("mfa_verify", user.Username, user.ID, "", true, "MFA verified ("+method+"), fully authenticated")
	log.Printf("[AUTH] MFA verified: %s — method=%s, fully authenticated", user.Username, method)

	return &models.MFAVerifyResponse{
		Status:    "authenticated",
		Message:   "Multi-factor authentication successful",
		AuthToken: authToken,
	}, nil
}

// containsMFAMethod checks if a method is present in the list
func containsMFAMethod(methods []string, method string) bool {
	for _, m := range methods {
		if m == method {
			return true
		}
	}
	return false
}

// ValidateToken validates a JWT auth token and returns the claims (requires MFADone=true)
func (svc *Service) ValidateToken(tokenString string) (*CustomClaims, error) {
	return svc.JWT.ValidateAuthToken(tokenString)
}

// ParseToken validates a JWT auth token without checking MFADone.
// Used by the MFA step-up flow to accept tokens before MFA completion.
func (svc *Service) ParseToken(tokenString string) (*CustomClaims, error) {
	return svc.JWT.ParseAuthTokenForAudience(tokenString, AgentTokenAudience)
}

// audit records an event in the audit log
func (svc *Service) audit(eventType, username, userID, sourceIP string, success bool, details string) {
	entryID, _ := util.GenerateID("aud")
	svc.Store.AddAuditEntry(&models.AuditEntry{
		ID:        entryID,
		Timestamp: time.Now(),
		EventType: eventType,
		UserID:    userID,
		Username:  username,
		SourceIP:  sourceIP,
		Success:   success,
		Details:   details,
	})
}
