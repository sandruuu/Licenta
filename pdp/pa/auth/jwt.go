package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	AgentTokenAudience      = "ztna-pdp"
	AgentSessionAudience    = "ztna-agent-api"
	AgentSessionPurpose     = "ztna.agent_session"
	EnrollmentTokenAudience = "ztna-enrollment"
	EnrollmentTokenPurpose  = "device_enrollment"
	EnrollmentTokenTTL      = 5 * time.Minute
)

// JWTManager handles creation and validation of JSON Web Tokens using ES256 (ECDSA P-256).
type JWTManager struct {
	privateKey            *ecdsa.PrivateKey
	publicKey             *ecdsa.PublicKey
	keyID                 string // kid for JWKS
	tokenExpiry           time.Duration
	mfaTokenExpiry        time.Duration
	enrollmentTokenExpiry time.Duration
	issuer                string
}

type ConfirmationClaims struct {
	CertificateThumbprintSHA256 string `json:"x5t#S256,omitempty"`
}

// CustomClaims extends the standard JWT claims with application-specific fields
type CustomClaims struct {
	jwt.RegisteredClaims
	UserID                      string              `json:"user_id"`
	Username                    string              `json:"username"`
	Role                        string              `json:"role"`
	TenantID                    string              `json:"tenant_id,omitempty"`
	DeviceID                    string              `json:"device_id,omitempty"`
	SessionID                   string              `json:"session_id,omitempty"`
	UserSID                     string              `json:"user_sid,omitempty"`
	LocalUserSIDHash            string              `json:"local_user_sid_hash,omitempty"`
	WindowsLogonSessionID       string              `json:"windows_logon_session_id,omitempty"`
	WindowsSessionID            string              `json:"windows_session_id,omitempty"`
	CertificateThumbprintSHA256 string              `json:"x5t#S256,omitempty"`
	Confirmation                *ConfirmationClaims `json:"cnf,omitempty"`
	Purpose                     string              `json:"purpose,omitempty"`
	Nonce                       string              `json:"nonce,omitempty"` // OIDC nonce for replay protection (§3.1.2.1)
	MFADone                     bool                `json:"mfa_done"`
	ACR                         string              `json:"acr,omitempty"`
	AMR                         []string            `json:"amr,omitempty"`
	Scopes                      []string            `json:"scope,omitempty"`
	PolicyEpoch                 int                 `json:"policy_epoch,omitempty"`
}

type AgentSessionTokenRequest struct {
	SessionID                   string
	UserID                      string
	Username                    string
	Role                        string
	TenantID                    string
	DeviceID                    string
	LocalUserSIDHash            string
	WindowsLogonSessionID       string
	WindowsSessionID            string
	CertificateThumbprintSHA256 string
	PostureRevision             string
	PolicyEpoch                 int
	Scopes                      []string
	ACR                         string
	AMR                         []string
}

// MFAClaims is a temporary token issued for MFA step-up verification.
// It carries the user's available MFA methods so the login page can present
// the correct verification UI without an additional API call.
type MFAClaims struct {
	jwt.RegisteredClaims
	UserID     string   `json:"user_id"`
	Username   string   `json:"username"`
	Role       string   `json:"role"`
	MFAMethods []string `json:"mfa_methods"` // configured methods: "totp", "webauthn"
	Purpose    string   `json:"purpose"`     // always "mfa_verification"
}

// JWK represents a JSON Web Key for the JWKS endpoint
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

// JWKS is the JSON Web Key Set returned by /.well-known/jwks.json
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// NewJWTManager creates a new JWT manager with an in-memory ES256 signing key.
func NewJWTManager(privKey *ecdsa.PrivateKey, tokenExpiry, mfaTokenExpiry time.Duration, enrollmentTokenExpiry ...time.Duration) (*JWTManager, error) {
	if privKey == nil {
		return nil, fmt.Errorf("JWT signing key is nil")
	}
	enrollmentTTL := EnrollmentTokenTTL
	if len(enrollmentTokenExpiry) > 0 && enrollmentTokenExpiry[0] > 0 {
		enrollmentTTL = enrollmentTokenExpiry[0]
	}
	// Compute key ID from public key thumbprint (SHA-256)
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal JWT public key: %w", err)
	}
	thumbprint := sha256.Sum256(pubDER)
	kid := hex.EncodeToString(thumbprint[:8])

	return &JWTManager{
		privateKey:            privKey,
		publicKey:             &privKey.PublicKey,
		keyID:                 kid,
		tokenExpiry:           tokenExpiry,
		mfaTokenExpiry:        mfaTokenExpiry,
		enrollmentTokenExpiry: enrollmentTTL,
		issuer:                "ztna-pdp",
	}, nil
}

// GenerateJWTSigningKey creates a new ECDSA P-256 signing key for JWTs.
func GenerateJWTSigningKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate JWT signing key: %w", err)
	}
	return key, nil
}

// GenerateAuthToken creates a PA API authentication JWT.
// mfaDone indicates whether MFA has been completed — at login time this is false;
// after a successful MFA step-up verification it is set to true.
// The nonce parameter is optional — when non-empty, it is included in the token for OIDC
// replay protection per OIDC Core 1.0 §3.1.2.1.
func (j *JWTManager) GenerateAuthToken(userID, username, role, deviceID, nonce string, mfaDone bool) (string, error) {
	now := time.Now()
	jti, err := generateJTI()
	if err != nil {
		return "", fmt.Errorf("generate JTI: %w", err)
	}
	acr := "urn:ztna:loa:1"
	amr := []string{"pwd"}
	if mfaDone {
		acr = "urn:ztna:loa:2"
		amr = []string{"pwd", "mfa"}
	}

	claims := CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{AgentTokenAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(j.tokenExpiry)),
			NotBefore: jwt.NewNumericDate(now),
			ID:        jti,
		},
		UserID:   userID,
		Username: username,
		Role:     role,
		DeviceID: deviceID,
		Nonce:    nonce,
		MFADone:  mfaDone,
		ACR:      acr,
		AMR:      amr,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = j.keyID
	return token.SignedString(j.privateKey)
}

func (j *JWTManager) GenerateAgentSessionToken(req AgentSessionTokenRequest) (string, time.Time, error) {
	if strings.TrimSpace(req.SessionID) == "" {
		return "", time.Time{}, fmt.Errorf("session_id is required")
	}
	if strings.TrimSpace(req.UserID) == "" {
		return "", time.Time{}, fmt.Errorf("user_id is required")
	}
	if strings.TrimSpace(req.DeviceID) == "" {
		return "", time.Time{}, fmt.Errorf("device_id is required")
	}
	if strings.TrimSpace(req.CertificateThumbprintSHA256) == "" {
		return "", time.Time{}, fmt.Errorf("device certificate thumbprint is required")
	}

	now := time.Now()
	expiresAt := now.Add(j.tokenExpiry)
	jti, err := generateJTI()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("generate JTI: %w", err)
	}
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = []string{"catalog:read", "posture:write", "flow:authorize", "session:renew", "session:revoke"}
	}
	acr := strings.TrimSpace(req.ACR)
	if acr == "" {
		acr = "urn:ztna:loa:1"
	}
	amr := req.AMR
	if len(amr) == 0 {
		amr = []string{"idp"}
	}
	certificateThumbprint := strings.ToLower(strings.TrimSpace(req.CertificateThumbprintSHA256))

	claims := CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.issuer,
			Subject:   "device:" + strings.TrimSpace(req.DeviceID),
			Audience:  jwt.ClaimStrings{AgentSessionAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
			ID:        jti,
		},
		UserID:                      strings.TrimSpace(req.UserID),
		Username:                    strings.TrimSpace(req.Username),
		Role:                        strings.TrimSpace(req.Role),
		TenantID:                    strings.TrimSpace(req.TenantID),
		DeviceID:                    strings.TrimSpace(req.DeviceID),
		SessionID:                   strings.TrimSpace(req.SessionID),
		LocalUserSIDHash:            strings.TrimSpace(req.LocalUserSIDHash),
		WindowsLogonSessionID:       strings.TrimSpace(req.WindowsLogonSessionID),
		WindowsSessionID:            strings.TrimSpace(req.WindowsSessionID),
		CertificateThumbprintSHA256: certificateThumbprint,
		Confirmation:                &ConfirmationClaims{CertificateThumbprintSHA256: certificateThumbprint},
		Purpose:                     AgentSessionPurpose,
		MFADone:                     true,
		ACR:                         acr,
		AMR:                         append([]string(nil), amr...),
		Scopes:                      append([]string(nil), scopes...),
		PolicyEpoch:                 req.PolicyEpoch,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = j.keyID
	signed, err := token.SignedString(j.privateKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign agent session token: %w", err)
	}
	return signed, expiresAt, nil
}

// GenerateEnrollmentToken mints a short-lived, device-bound bearer token for
// EST simpleenroll. It is intentionally separate from resource-access tokens
// so enrollment credentials cannot be replayed against the PA API audience.
func (j *JWTManager) GenerateEnrollmentToken(userID, username, role, deviceID, nonce string) (string, time.Duration, error) {
	return j.GenerateEnrollmentTokenForUserSID(userID, username, role, deviceID, nonce, "")
}

// GenerateEnrollmentTokenForUserSID mints a short-lived, device-bound bearer
// token for EST simpleenroll and optionally binds it to a Windows user SID.
func (j *JWTManager) GenerateEnrollmentTokenForUserSID(userID, username, role, deviceID, nonce, userSID string) (string, time.Duration, error) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return "", 0, fmt.Errorf("device_id is required")
	}
	now := time.Now()
	jti, err := generateJTI()
	if err != nil {
		return "", 0, fmt.Errorf("generate JTI: %w", err)
	}

	claims := CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{EnrollmentTokenAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(j.enrollmentTokenExpiry)),
			NotBefore: jwt.NewNumericDate(now),
			ID:        jti,
		},
		UserID:   userID,
		Username: username,
		Role:     role,
		DeviceID: deviceID,
		UserSID:  strings.TrimSpace(userSID),
		Purpose:  EnrollmentTokenPurpose,
		Nonce:    strings.TrimSpace(nonce),
		MFADone:  false,
		ACR:      "urn:ztna:loa:1",
		AMR:      []string{"pwd"},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = j.keyID
	signed, err := token.SignedString(j.privateKey)
	if err != nil {
		return "", 0, fmt.Errorf("sign enrollment token: %w", err)
	}
	return signed, j.enrollmentTokenExpiry, nil
}

// ParseAuthTokenForAudience validates the JWT and additionally requires that
// the `aud` claim contains expectedAudience.
func (j *JWTManager) ParseAuthTokenForAudience(tokenString, expectedAudience string) (*CustomClaims, error) {
	claims, err := j.ParseAuthToken(tokenString)
	if err != nil {
		return nil, err
	}
	if expectedAudience == "" {
		return claims, nil
	}
	for _, aud := range claims.Audience {
		if aud == expectedAudience {
			return claims, nil
		}
	}
	return nil, fmt.Errorf("token audience mismatch: expected %q, got %v", expectedAudience, []string(claims.Audience))
}

// ParseEnrollmentToken validates the dedicated EST enrollment audience and
// purpose. Replay protection is enforced by the API/store layer after parsing.
func (j *JWTManager) ParseEnrollmentToken(tokenString string) (*CustomClaims, error) {
	claims, err := j.ParseAuthTokenForAudience(tokenString, EnrollmentTokenAudience)
	if err != nil {
		return nil, err
	}
	if claims.Purpose != EnrollmentTokenPurpose {
		return nil, fmt.Errorf("token purpose mismatch: expected %q", EnrollmentTokenPurpose)
	}
	if strings.TrimSpace(claims.DeviceID) == "" {
		return nil, fmt.Errorf("enrollment token is not bound to a device_id")
	}
	if strings.TrimSpace(claims.ID) == "" {
		return nil, fmt.Errorf("enrollment token has no JTI")
	}
	if claims.ExpiresAt == nil {
		return nil, fmt.Errorf("enrollment token has no expiry")
	}
	return claims, nil
}

// GenerateMFAToken creates a temporary token for the MFA step-up verification.
// The token carries the user's role and configured MFA methods so the
// downstream verification step can enforce method validity.
func (j *JWTManager) GenerateMFAToken(userID, username, role string, mfaMethods []string) (string, error) {
	now := time.Now()
	jti, err := generateJTI()
	if err != nil {
		return "", fmt.Errorf("generate JTI: %w", err)
	}

	claims := MFAClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.issuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(j.mfaTokenExpiry)),
			NotBefore: jwt.NewNumericDate(now),
			ID:        jti,
		},
		UserID:     userID,
		Username:   username,
		Role:       role,
		MFAMethods: mfaMethods,
		Purpose:    "mfa_verification",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = j.keyID
	return token.SignedString(j.privateKey)
}

// ParseAuthToken validates the JWT signature and expiry but does NOT check
// audience or MFADone.
// Use this for endpoints that accept tokens before MFA completion (e.g. MFA step-up).
func (j *JWTManager) ParseAuthToken(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

// ValidateAuthToken validates a full authentication JWT and requires MFADone=true.
// Used by the auth middleware for normal API access.
func (j *JWTManager) ValidateAuthToken(tokenString string) (*CustomClaims, error) {
	claims, err := j.ParseAuthTokenForAudience(tokenString, AgentTokenAudience)
	if err != nil {
		return nil, err
	}

	if !claims.MFADone {
		return nil, fmt.Errorf("MFA not completed")
	}

	return claims, nil
}

// ValidateMFAToken validates and parses a temporary MFA token
func (j *JWTManager) ValidateMFAToken(tokenString string) (*MFAClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &MFAClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("parse MFA token: %w", err)
	}

	claims, ok := token.Claims.(*MFAClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid MFA token claims")
	}

	if claims.Purpose != "mfa_verification" {
		return nil, fmt.Errorf("token is not an MFA token")
	}

	return claims, nil
}

// GetJWKS returns the JWKS containing the public key for token verification
func (j *JWTManager) GetJWKS() *JWKS {
	return &JWKS{
		Keys: []JWK{
			{
				Kty: "EC",
				Crv: "P-256",
				X:   base64.RawURLEncoding.EncodeToString(j.publicKey.X.Bytes()),
				Y:   base64.RawURLEncoding.EncodeToString(j.publicKey.Y.Bytes()),
				Kid: j.keyID,
				Use: "sig",
				Alg: "ES256",
			},
		},
	}
}

// GetJWKSJSON returns the JWKS as a JSON byte slice
func (j *JWTManager) GetJWKSJSON() ([]byte, error) {
	return json.Marshal(j.GetJWKS())
}

// generateJTI generates a unique JWT ID
func generateJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
