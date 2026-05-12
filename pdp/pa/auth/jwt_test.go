package auth

import (
	"path/filepath"
	"testing"
	"time"
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
	if _, err := manager.ParseAuthTokenForAudience(authToken, "ztna-gateway"); err == nil {
		t.Fatalf("ParseAuthTokenForAudience accepted gateway audience")
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
	dir := t.TempDir()
	manager, err := NewJWTManager(filepath.Join(dir, "jwt.key"), filepath.Join(dir, "jwt.pub"), time.Hour, time.Minute)
	if err != nil {
		t.Fatalf("NewJWTManager returned error: %v", err)
	}
	return manager
}
