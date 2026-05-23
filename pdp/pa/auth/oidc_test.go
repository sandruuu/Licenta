package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestNativeConnectAppLoopbackRedirectValidation(t *testing.T) {
	mgr := newTestOIDCManager()
	mgr.RegisterNativeConnectAppClient()

	client, err := mgr.ValidateClientID(NativeConnectAppClientID)
	if err != nil {
		t.Fatalf("ValidateClientID() error = %v", err)
	}
	if !client.Public || !client.RequirePKCE {
		t.Fatalf("native client must be public and require PKCE: %+v", client)
	}

	valid := []string{
		"http://127.0.0.1:49152/callback",
		"http://localhost:12345/callback",
	}
	for _, redirectURI := range valid {
		if !mgr.ValidateRedirectURI(client, redirectURI) {
			t.Fatalf("ValidateRedirectURI(%q) = false, want true", redirectURI)
		}
	}

	invalid := []string{
		"https://127.0.0.1:49152/callback",
		"http://127.0.0.1/callback",
		"http://127.0.0.1:49152/not-callback",
		"http://127.0.0.1:49152/callback/extra",
		"http://localhost:12345/not-callback",
		"http://evil.example:49152/callback",
		"http://127.0.0.1.evil.example:49152/callback",
	}
	for _, redirectURI := range invalid {
		if mgr.ValidateRedirectURI(client, redirectURI) {
			t.Fatalf("ValidateRedirectURI(%q) = true, want false", redirectURI)
		}
	}
	if !IsNativeEndpointClientID(NativeConnectAppClientID) {
		t.Fatalf("native endpoint client helper rejected connect-app")
	}
	if IsNativeEndpointClientID("trustagent") || IsNativeEndpointClientID("gateway") {
		t.Fatalf("native endpoint client helper accepted unrelated client ID")
	}
}

func TestExchangeCodeRequiresAndVerifiesPKCES256(t *testing.T) {
	mgr := newTestOIDCManager()
	mgr.RegisterNativeConnectAppClient()

	verifier := "correct-code-verifier-with-enough-entropy"
	challenge := pkceChallenge(verifier)

	sess, err := mgr.CreateAuthorizeSession(
		NativeConnectAppClientID,
		"http://127.0.0.1:49152/callback",
		"opaque-state",
		"openid profile offline_access",
		challenge,
		"S256",
		"nonce-1",
		"device-1",
		"host-1",
		"",
	)
	if err != nil {
		t.Fatalf("CreateAuthorizeSession() error = %v", err)
	}
	authCode, err := mgr.CompleteAuthorizeSession(sess.ID, "jwt", "user-1", "alice", "user", false)
	if err != nil {
		t.Fatalf("CompleteAuthorizeSession() error = %v", err)
	}

	if _, _, err := mgr.ExchangeCode(authCode.Code, NativeConnectAppClientID, "", authCode.RedirectURI, "wrong-verifier"); err == nil || !strings.Contains(err.Error(), "PKCE") {
		t.Fatalf("ExchangeCode() with wrong verifier error = %v, want PKCE error", err)
	}

	exchanged, refreshToken, err := mgr.ExchangeCode(authCode.Code, NativeConnectAppClientID, "", authCode.RedirectURI, verifier)
	if err != nil {
		t.Fatalf("ExchangeCode() error = %v", err)
	}
	if exchanged.DeviceID != "device-1" || exchanged.MFADone {
		t.Fatalf("exchanged code lost device/MFA state: device=%q mfa=%v", exchanged.DeviceID, exchanged.MFADone)
	}
	if refreshToken == "" {
		t.Fatal("ExchangeCode() returned empty refresh token")
	}
	mgr.mu.RLock()
	storedRefresh := mgr.RefreshTokens[refreshToken]
	mgr.mu.RUnlock()
	if storedRefresh == nil {
		t.Fatalf("refresh token %q was not stored", refreshToken)
	}
	if storedRefresh.DeviceID != "device-1" || storedRefresh.MFADone {
		t.Fatalf("refresh token lost device/MFA state: device=%q mfa=%v", storedRefresh.DeviceID, storedRefresh.MFADone)
	}

	if _, _, err := mgr.ExchangeCode(authCode.Code, NativeConnectAppClientID, "", authCode.RedirectURI, verifier); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("ExchangeCode() replay error = %v, want already used", err)
	}
}

func TestExchangeCodeRejectsMissingPKCEChallenge(t *testing.T) {
	mgr := newTestOIDCManager()
	mgr.RegisterNativeConnectAppClient()

	sess, err := mgr.CreateAuthorizeSession(
		NativeConnectAppClientID,
		"http://127.0.0.1:49152/callback",
		"opaque-state",
		"openid",
		"",
		"",
		"nonce-1",
		"device-1",
		"host-1",
		"",
	)
	if err != nil {
		t.Fatalf("CreateAuthorizeSession() error = %v", err)
	}
	authCode, err := mgr.CompleteAuthorizeSession(sess.ID, "jwt", "user-1", "alice", "user", false)
	if err != nil {
		t.Fatalf("CompleteAuthorizeSession() error = %v", err)
	}

	if _, _, err := mgr.ExchangeCode(authCode.Code, NativeConnectAppClientID, "", authCode.RedirectURI, "verifier"); err == nil || !strings.Contains(err.Error(), "code_challenge") {
		t.Fatalf("ExchangeCode() error = %v, want missing code_challenge", err)
	}
}

func newTestOIDCManager() *OIDCManager {
	return NewOIDCManager(5*time.Minute, time.Minute, 24*time.Hour, 30*time.Second)
}

func pkceChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
