package idp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTManager handles creation and validation of JSON Web Tokens using ES256 (ECDSA P-256).
type JWTManager struct {
	privateKey     *ecdsa.PrivateKey
	publicKey      *ecdsa.PublicKey
	keyID          string // kid for JWKS
	tokenExpiry    time.Duration
	mfaTokenExpiry time.Duration
	issuer         string
}

// CustomClaims extends the standard JWT claims with application-specific fields
type CustomClaims struct {
	jwt.RegisteredClaims
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	DeviceID string `json:"device_id,omitempty"`
	Nonce    string `json:"nonce,omitempty"` // OIDC nonce for replay protection (§3.1.2.1)
	MFADone  bool   `json:"mfa_done"`
}

// MFAClaims is a temporary token issued for MFA step-up verification.
// It carries the user's available MFA methods so the login page can present
// the correct verification UI without an additional API call.
type MFAClaims struct {
	jwt.RegisteredClaims
	UserID     string   `json:"user_id"`
	Username   string   `json:"username"`
	Role       string   `json:"role"`
	MFAMethods []string `json:"mfa_methods"` // configured methods: "totp", "webauthn", "push"
	Purpose    string   `json:"purpose"`     // always "mfa_verification"
}

// JWK represents a JSON Web Key for the JWKS endpoint
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

// JWKS is the JSON Web Key Set returned by /.well-known/jwks.json
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// NewJWTManager creates a new JWT manager with ES256 signing.
// If keyPath/pubPath exist, loads keys from disk; otherwise generates and saves them.
func NewJWTManager(keyPath, pubPath string, tokenExpiry, mfaTokenExpiry time.Duration) (*JWTManager, error) {
	var privKey *ecdsa.PrivateKey
	var err error

	keyData, keyErr := os.ReadFile(keyPath)
	if keyErr == nil {
		privKey, err = parseECPrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("parse JWT signing key: %w", err)
		}
	} else {
		privKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate JWT signing key: %w", err)
		}
		keyPEM, err := marshalECPrivateKey(privKey)
		if err != nil {
			return nil, err
		}
		pubPEM, err := marshalECPublicKey(&privKey.PublicKey)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
			return nil, fmt.Errorf("save JWT signing key: %w", err)
		}
		if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
			return nil, fmt.Errorf("save JWT public key: %w", err)
		}
	}

	// Compute key ID from public key thumbprint (SHA-256)
	pubDER, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	thumbprint := sha256.Sum256(pubDER)
	kid := hex.EncodeToString(thumbprint[:8])

	return &JWTManager{
		privateKey:     privKey,
		publicKey:      &privKey.PublicKey,
		keyID:          kid,
		tokenExpiry:    tokenExpiry,
		mfaTokenExpiry: mfaTokenExpiry,
		issuer:         "ztna-cloud",
	}, nil
}

// GenerateAuthToken creates an authentication JWT.
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

	claims := CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.issuer,
			Subject:   userID,
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
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = j.keyID
	return token.SignedString(j.privateKey)
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

// ParseAuthToken validates the JWT signature and expiry but does NOT check MFADone.
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
	claims, err := j.ParseAuthToken(tokenString)
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

func parseECPrivateKey(pemData []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		pkcs8Key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse EC key: %w", err)
		}
		ecKey, ok := pkcs8Key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not ECDSA")
		}
		return ecKey, nil
	}
	return key, nil
}

func marshalECPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal EC private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func marshalECPublicKey(key *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal EC public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
