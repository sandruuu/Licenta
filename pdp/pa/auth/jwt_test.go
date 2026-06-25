package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestEnrollmentTokenUsesDedicatedAudienceAndPurpose(t *testing.T) {
	manager := newTestJWTManager(t)
	token, ttl, err := manager.GenerateEnrollmentToken("user-1", "user@example.com", "user", "device-1", "nonce-1")
	if err != nil {
		t.Fatalf("GenerateEnrollmentToken returned error: %v", err)
	}
	if ttl != EnrollmentTokenTTL {
		t.Fatalf("ttl = %s, want %s", ttl, EnrollmentTokenTTL)
	}
	claims, err := manager.ParseEnrollmentToken(token)
	if err != nil {
		t.Fatalf("ParseEnrollmentToken returned error: %v", err)
	}
	if claims.DeviceID != "device-1" || claims.Purpose != EnrollmentTokenPurpose || claims.Nonce != "nonce-1" {
		t.Fatalf("claims = %+v", claims)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != EnrollmentTokenAudience {
		t.Fatalf("audience = %v", claims.Audience)
	}
	if claims.ID == "" || claims.ExpiresAt == nil {
		t.Fatalf("JTI/expiry missing: %+v", claims.RegisteredClaims)
	}
}

func TestAuthTokenUsesAgentAudience(t *testing.T) {
	manager := newTestJWTManager(t)
	authToken, err := manager.GenerateAuthToken("user-1", "user@example.com", "user", "device-1", "", false)
	if err != nil {
		t.Fatalf("GenerateAuthToken returned error: %v", err)
	}
	claims, err := manager.ParseAuthTokenForAudience(authToken, AgentTokenAudience)
	if err != nil {
		t.Fatalf("ParseAuthTokenForAudience returned error: %v", err)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != AgentTokenAudience {
		t.Fatalf("audience = %v", claims.Audience)
	}
	if _, err := manager.ParseAuthTokenForAudience(authToken, "trustgateway"); err == nil {
		t.Fatalf("ParseAuthTokenForAudience accepted gateway audience")
	}
}

func TestAuthTokenCanCarryPurpose(t *testing.T) {
	manager := newTestJWTManager(t)
	authToken, err := manager.GenerateAuthTokenWithPurpose("user-1", "user@example.com", "platform_admin", "", "", true, PasskeyEnrollmentPurpose)
	if err != nil {
		t.Fatalf("GenerateAuthTokenWithPurpose returned error: %v", err)
	}
	claims, err := manager.ValidateAuthToken(authToken)
	if err != nil {
		t.Fatalf("ValidateAuthToken returned error: %v", err)
	}
	if claims.Purpose != PasskeyEnrollmentPurpose {
		t.Fatalf("purpose = %q, want %q", claims.Purpose, PasskeyEnrollmentPurpose)
	}
}

func TestAuthTokenCanCarrySessionAndCustomTTL(t *testing.T) {
	manager := newTestJWTManager(t)
	authToken, err := manager.GenerateAuthTokenWithSession("user-1", "user@example.com", "platform_admin", "", "", true, "", "ads-session-1", 2*time.Minute)
	if err != nil {
		t.Fatalf("GenerateAuthTokenWithSession returned error: %v", err)
	}
	claims, err := manager.ValidateAuthToken(authToken)
	if err != nil {
		t.Fatalf("ValidateAuthToken returned error: %v", err)
	}
	if claims.SessionID != "ads-session-1" {
		t.Fatalf("session_id = %q, want %q", claims.SessionID, "ads-session-1")
	}
	if claims.ExpiresAt == nil || time.Until(claims.ExpiresAt.Time) > 3*time.Minute {
		t.Fatalf("custom ttl was not applied: expires_at=%v", claims.ExpiresAt)
	}
}

func TestParseAuthTokenRejectsWrongIssuer(t *testing.T) {
	manager := newTestJWTManager(t)
	token := jwt.NewWithClaims(jwt.SigningMethodES256, CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "unexpected-issuer",
			Subject:   "user-1",
			Audience:  jwt.ClaimStrings{AgentTokenAudience},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ID:        "jti-1",
		},
		UserID:   "user-1",
		Username: "user@example.com",
		Role:     "user",
		MFADone:  true,
	})
	signed, err := token.SignedString(manager.privateKey)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	if _, err := manager.ParseAuthTokenForAudience(signed, AgentTokenAudience); err == nil {
		t.Fatalf("ParseAuthTokenForAudience accepted token with wrong issuer")
	}
}

func TestParseAuthTokenRejectsNonES256ECDSA(t *testing.T) {
	manager := newTestJWTManager(t)
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES384, CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    manager.issuer,
			Subject:   "user-1",
			Audience:  jwt.ClaimStrings{AgentTokenAudience},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ID:        "jti-1",
		},
		UserID:   "user-1",
		Username: "user@example.com",
		Role:     "user",
		MFADone:  true,
	})
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	if _, err := manager.ParseAuthTokenForAudience(signed, AgentTokenAudience); err == nil {
		t.Fatalf("ParseAuthTokenForAudience accepted ECDSA token that was not ES256")
	}
}

func TestEnrollmentParserRejectsAgentToken(t *testing.T) {
	manager := newTestJWTManager(t)
	authToken, err := manager.GenerateAuthToken("user-1", "user@example.com", "user", "device-1", "", false)
	if err != nil {
		t.Fatalf("GenerateAuthToken returned error: %v", err)
	}
	if _, err := manager.ParseEnrollmentToken(authToken); err == nil {
		t.Fatalf("ParseEnrollmentToken accepted PA auth token")
	}
}

func TestEnrollmentTokenRequiresDeviceID(t *testing.T) {
	manager := newTestJWTManager(t)
	if _, _, err := manager.GenerateEnrollmentToken("user-1", "user@example.com", "user", "", "nonce-1"); err == nil {
		t.Fatalf("GenerateEnrollmentToken accepted empty device_id")
	}
}

func TestEnrollmentTokenCanBindUserSID(t *testing.T) {
	manager := newTestJWTManager(t)
	token, _, err := manager.GenerateEnrollmentTokenForUserSID("user-1", "user@example.com", "user", "device-1", "nonce-1", "S-1-5-21-1000")
	if err != nil {
		t.Fatalf("GenerateEnrollmentTokenForUserSID returned error: %v", err)
	}
	claims, err := manager.ParseEnrollmentToken(token)
	if err != nil {
		t.Fatalf("ParseEnrollmentToken returned error: %v", err)
	}
	if claims.UserSID != "S-1-5-21-1000" {
		t.Fatalf("user_sid = %q", claims.UserSID)
	}
}

func newTestJWTManager(t *testing.T) *JWTManager {
	t.Helper()
	key, err := GenerateJWTSigningKey()
	if err != nil {
		t.Fatalf("GenerateJWTSigningKey returned error: %v", err)
	}
	manager, err := NewJWTManager(key, time.Hour)
	if err != nil {
		t.Fatalf("NewJWTManager returned error: %v", err)
	}
	return manager
}
