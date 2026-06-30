package auth

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"strings"
	"time"

	"pdp/config"
	"pdp/mfa"
	"pdp/models"
	"pdp/pki"
	"pdp/runtime/redisstate"
	"pdp/store"
	"pdp/util"
)

// Service coordinates identity and authentication services owned by the PA.
// It combines UserManager, JWTManager, TOTP MFA, WebAuthn, and federation.
type Service struct {
	Users      *UserManager
	JWT        *JWTManager
	WebAuthn   *mfa.WebAuthnProvider // nil if WebAuthn not configured
	Federation *FederationProvider
	Secrets    *SecretProtector
	Store      *store.Store
	Runtime    *redisstate.Client
	Cfg        *config.Config
}

// New creates a new authentication service.
func New(cfg *config.Config, s *store.Store, runtimeState *redisstate.Client) *Service {
	if cfg == nil {
		log.Fatal("[AUTH] PDP config is required")
	}
	cfg.ApplyDefaults()

	jwtKey, err := loadJWTSigningKey(cfg, runtimeState)
	if err != nil {
		log.Fatalf("[AUTH] Failed to load JWT signing key: %v", err)
	}

	jwtMgr, err := NewJWTManager(jwtKey, cfg.Runtime.AdminAccessTokenTTL, cfg.Runtime.OIDCEnrollmentTokenTTL)
	if err != nil {
		log.Fatalf("[AUTH] Failed to initialize JWT manager: %v", err)
	}
	log.Printf("[AUTH] JWT signing initialized (ES256, kid=%s)", jwtMgr.keyID)

	secretProtector, err := NewSecretProtector(cfg, runtimeState)
	if err != nil {
		log.Fatalf("[AUTH] Failed to initialize MFA secret protection: %v", err)
	}
	return &Service{
		Users:      NewUserManager(s, secretProtector),
		JWT:        jwtMgr,
		WebAuthn:   mfa.NewWebAuthnProvider(cfg, runtimeState),
		Federation: NewFederationProvider(runtimeState, cfg.Public.OIDCDefaultScopes, cfg.Public.OIDCDefaultClaimMapping, cfg.Runtime.FederationCacheTTL, cfg.Runtime.FederationHTTPTimeout),
		Secrets:    secretProtector,
		Store:      s,
		Runtime:    runtimeState,
		Cfg:        cfg,
	}
}

func loadJWTSigningKey(cfg *config.Config, runtimeState *redisstate.Client) (*ecdsa.PrivateKey, error) {
	if strings.TrimSpace(cfg.PKIURL) == "" ||
		strings.TrimSpace(cfg.PKIToken) == "" ||
		strings.TrimSpace(cfg.JWTTransitKey) == "" ||
		strings.TrimSpace(cfg.JWTKeyEncryptedPath) == "" {
		return nil, fmt.Errorf("vault transit configuration is required for JWT signing key")
	}
	if runtimeState == nil {
		return nil, fmt.Errorf("redis runtime state is required for JWT signing key lock")
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

	var key *ecdsa.PrivateKey
	err := runtimeState.WithLock(context.Background(), "jwt-signing-key", 2*time.Minute, 2*time.Minute, func() error {
		var err error
		key, err = pki.RestoreOrCreateNamedKey(context.Background(), vaultCfg, cfg.JWTKeyEncryptedPath, "JWT signing")
		return err
	})
	return key, err
}

// Login handles primary authentication with email and password.
// MFA is deferred to resource-access step-up challenges.
func (svc *Service) Login(req models.LoginRequest) (*models.LoginResponse, error) {
	identifier := req.Identifier()
	locked, until, err := svc.Runtime.IsLockedOut(identifier)
	if err != nil {
		return nil, fmt.Errorf("check login lockout: %w", err)
	}
	if locked {
		svc.audit("login", identifier, "", "", false,
			"Account locked until "+until.Format(time.RFC3339))
		return &models.LoginResponse{
			Status:  "denied",
			Message: "Account temporarily locked due to too many failed attempts",
		}, nil
	}

	user, err := svc.Users.AuthenticateByEmail(identifier, req.Password)
	if err != nil {
		_ = svc.Runtime.RecordFailedLogin(identifier, svc.Cfg.MaxLoginAttempts, svc.Cfg.LockoutDuration)
		svc.audit("login", identifier, "", "", false, "Invalid credentials")
		return &models.LoginResponse{
			Status:  "denied",
			Message: "Invalid credentials",
		}, nil
	}

	_ = svc.Runtime.ResetLoginAttempts(identifier)

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
