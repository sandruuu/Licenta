package idp

import (
	"log"
	"os"
	"path/filepath"
	"time"

	"cloud/config"
	"cloud/mfa"
	"cloud/models"
	"cloud/store"
	"cloud/util"
)

// IdentityProvider coordinates all identity and authentication services.
// It combines UserManager (user CRUD + password auth), JWTManager (token issuance),
// TOTP-based MFA, and OIDC authorization into a unified authentication flow.
type IdentityProvider struct {
	Users      *UserManager
	JWT        *JWTManager
	OIDC       *OIDCManager
	WebAuthn   *mfa.WebAuthnProvider // nil if WebAuthn not configured
	Push       *mfa.PushProvider
	Federation *FederationProvider
	Store      *store.Store
	Cfg        *config.Config
}

// New creates a new IdentityProvider
func New(cfg *config.Config, s *store.Store) *IdentityProvider {
	// Ensure data directory exists for JWT keys
	keysDir := cfg.DataDir
	if keysDir == "" {
		keysDir = "./data"
	}
	os.MkdirAll(keysDir, 0755)

	jwtKeyPath := filepath.Join(keysDir, "jwt-signing.key")
	jwtPubPath := filepath.Join(keysDir, "jwt-signing.pub")

	jwtMgr, err := NewJWTManager(jwtKeyPath, jwtPubPath, cfg.JWTExpiry, cfg.MFATokenExpiry)
	if err != nil {
		log.Fatalf("[IDP] Failed to initialize JWT manager: %v", err)
	}
	log.Printf("[IDP] JWT signing initialized (ES256, kid=%s)", jwtMgr.keyID)

	return &IdentityProvider{
		Users:      NewUserManager(s),
		JWT:        jwtMgr,
		OIDC:       NewOIDCManager(),
		WebAuthn:   mfa.NewWebAuthnProvider(cfg),
		Push:       mfa.NewPushProvider(s),
		Federation: NewFederationProvider(),
		Store:      s,
		Cfg:        cfg,
	}
}

// Login handles primary authentication (username + password).
// Always returns an auth token with MFADone=false on success.
// MFA is never enforced at login — it is triggered later by the policy engine
// at resource access time (conditional access / step-up authentication).
func (idp *IdentityProvider) Login(req models.LoginRequest) (*models.LoginResponse, error) {
	// Check lockout
	if locked, until := idp.Store.IsLockedOut(req.Username); locked {
		idp.audit("login", req.Username, "", "", false,
			"Account locked until "+until.Format(time.RFC3339))
		return &models.LoginResponse{
			Status:  "denied",
			Message: "Account temporarily locked due to too many failed attempts",
		}, nil
	}

	// Authenticate with username + password
	user, err := idp.Users.Authenticate(req.Username, req.Password)
	if err != nil {
		// Record failed attempt
		idp.Store.RecordFailedLogin(req.Username, idp.Cfg.MaxLoginAttempts, idp.Cfg.LockoutDuration)
		idp.audit("login", req.Username, "", "", false, "Invalid credentials")
		return &models.LoginResponse{
			Status:  "denied",
			Message: "Invalid credentials",
		}, nil
	}

	// Reset failed attempts on successful password verification
	idp.Store.ResetLoginAttempts(req.Username)

	// Issue auth token with MFADone=false — MFA is handled at access time
	authToken, err := idp.JWT.GenerateAuthToken(user.ID, user.Username, user.Role, "", "", false)
	if err != nil {
		return nil, err
	}

	idp.audit("login", user.Username, user.ID, "", true, "Authenticated (MFA deferred to access time)")
	log.Printf("[IDP] Login: %s — authenticated (MFADone=false)", user.Username)

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
//   - "push": Push approval — not yet implemented
func (idp *IdentityProvider) VerifyMFA(req models.MFAVerifyRequest) (*models.MFAVerifyResponse, error) {
	// Validate the temporary MFA token
	claims, err := idp.JWT.ValidateMFAToken(req.MFAToken)
	if err != nil {
		idp.audit("mfa_verify", "", "", "", false, "Invalid MFA token: "+err.Error())
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
	user, exists := idp.Users.GetUser(claims.UserID)
	if !exists {
		return &models.MFAVerifyResponse{
			Status:  "denied",
			Message: "User not found",
		}, nil
	}

	if !containsMFAMethod(claims.MFAMethods, method) {
		idp.audit("mfa_verify", claims.Username, claims.UserID, "", false, "Method not configured: "+method)
		return &models.MFAVerifyResponse{
			Status:  "denied",
			Message: "MFA method not configured for this user",
		}, nil
	}

	// Dispatch to the correct MFA verifier
	switch method {
	case "totp":
		if err := idp.Users.VerifyMFA(claims.UserID, req.TOTPCode); err != nil {
			idp.audit("mfa_verify", claims.Username, claims.UserID, "", false, "Invalid TOTP code")
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
	case "push":
		// Push uses a separate begin/status polling flow via dedicated endpoints:
		//   POST /api/mfa/push/begin   → creates challenge, returns challenge_id
		//   GET  /api/mfa/push/status  → polls until approved/denied/expired
		// The generic VerifyMFA endpoint is not used for push.
		return &models.MFAVerifyResponse{
			Status:  "denied",
			Message: "Push uses the /api/mfa/push/* endpoints",
		}, nil
	default:
		return &models.MFAVerifyResponse{
			Status:  "denied",
			Message: "Unsupported MFA method: " + method,
		}, nil
	}

	// Issue full auth token with MFA completed
	authToken, err := idp.JWT.GenerateAuthToken(user.ID, user.Username, user.Role, "", "", true)
	if err != nil {
		return nil, err
	}

	idp.audit("mfa_verify", user.Username, user.ID, "", true, "MFA verified ("+method+"), fully authenticated")
	log.Printf("[IDP] MFA verified: %s — method=%s, fully authenticated", user.Username, method)

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
func (idp *IdentityProvider) ValidateToken(tokenString string) (*CustomClaims, error) {
	return idp.JWT.ValidateAuthToken(tokenString)
}

// ParseToken validates a JWT auth token without checking MFADone.
// Used by the MFA step-up flow to accept tokens before MFA completion.
func (idp *IdentityProvider) ParseToken(tokenString string) (*CustomClaims, error) {
	return idp.JWT.ParseAuthToken(tokenString)
}

// audit records an event in the audit log
func (idp *IdentityProvider) audit(eventType, username, userID, sourceIP string, success bool, details string) {
	entryID, _ := util.GenerateID("aud")
	idp.Store.AddAuditEntry(&models.AuditEntry{
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
