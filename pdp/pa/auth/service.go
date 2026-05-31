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
// It combines UserManager, JWTManager, TOTP MFA, WebAuthn, OIDC, and federation.
type Service struct {
	Users      *UserManager
	JWT        *JWTManager
	OIDC       *OIDCManager
	WebAuthn   *mfa.WebAuthnProvider // nil if WebAuthn not configured
	Federation *FederationProvider
	Secrets    *SecretProtector
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

	jwtMgr, err := NewJWTManager(jwtKey, cfg.JWTExpiry, cfg.Runtime.OIDCEnrollmentTokenTTL)
	if err != nil {
		log.Fatalf("[AUTH] Failed to initialize JWT manager: %v", err)
	}
	log.Printf("[AUTH] JWT signing initialized (ES256, kid=%s)", jwtMgr.keyID)

	secretProtector, err := NewSecretProtector(cfg)
	if err != nil {
		log.Fatalf("[AUTH] Failed to initialize MFA secret protection: %v", err)
	}
	if !secretProtector.Persistent() {
		log.Printf("[AUTH] MFA secret protection is using an in-memory key because data_dir is not configured")
	}

	return &Service{
		Users:      NewUserManager(s, secretProtector),
		JWT:        jwtMgr,
		OIDC:       NewOIDCManager(cfg.Runtime.OIDCAuthorizeSessionTTL, cfg.Runtime.OIDCAuthCodeTTL, cfg.Runtime.OIDCRefreshTokenTTL, cfg.Runtime.OIDCCleanupInterval),
		WebAuthn:   mfa.NewWebAuthnProvider(cfg),
		Federation: NewFederationProvider(cfg.Public.OIDCDefaultScopes, cfg.Public.OIDCDefaultClaimMapping, cfg.Runtime.FederationCacheTTL, cfg.Runtime.FederationHTTPTimeout),
		Secrets:    secretProtector,
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

// Login handles primary authentication with username and password.
// MFA is deferred to resource-access step-up challenges.
func (svc *Service) Login(req models.LoginRequest) (*models.LoginResponse, error) {
	if locked, until := svc.Store.IsLockedOut(req.Username); locked {
		svc.audit("login", req.Username, "", "", false,
			"Account locked until "+until.Format(time.RFC3339))
		return &models.LoginResponse{
			Status:  "denied",
			Message: "Account temporarily locked due to too many failed attempts",
		}, nil
	}

	user, err := svc.Users.Authenticate(req.Username, req.Password)
	if err != nil {
		svc.Store.RecordFailedLogin(req.Username, svc.Cfg.MaxLoginAttempts, svc.Cfg.LockoutDuration)
		svc.audit("login", req.Username, "", "", false, "Invalid credentials")
		return &models.LoginResponse{
			Status:  "denied",
			Message: "Invalid credentials",
		}, nil
	}

	svc.Store.ResetLoginAttempts(req.Username)

	svc.audit("login", user.Username, user.ID, "", true, "Primary authentication completed; MFA required")
	log.Printf("[AUTH] Login: %s - primary authentication completed; MFA required", user.Username)

	return &models.LoginResponse{
		Status:      "mfa_required",
		Message:     "MFA verification required",
		UserID:      user.ID,
		MFARequired: true,
	}, nil
}

// ValidateToken validates a JWT auth token and returns the claims (requires MFADone=true).
func (svc *Service) ValidateToken(tokenString string) (*CustomClaims, error) {
	return svc.JWT.ValidateAuthToken(tokenString)
}

// ParseToken validates a JWT auth token without checking MFADone.
// Used by the resource-access step-up flow to accept tokens before MFA completion.
func (svc *Service) ParseToken(tokenString string) (*CustomClaims, error) {
	return svc.JWT.ParseAuthTokenForAudience(tokenString, AgentTokenAudience)
}

// audit records an event in the audit log.
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
