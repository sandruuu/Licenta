package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"

	"pdp/models"

	"pdp/internal/testredis"
)

const (
	testEndpointClientID = "trustagent-endpoint"
	testRedirectURI      = "https://agent.example.com/callback"
)

func TestEndpointClientRedirectValidationUsesRegisteredURIs(t *testing.T) {
	mgr := newTestOIDCManager(t)
	registerTestEndpointClient(mgr)

	client, err := mgr.ValidateClientID(testEndpointClientID)
	if err != nil {
		t.Fatalf("ValidateClientID() error = %v", err)
	}
	if !client.Public || !client.RequirePKCE || !client.RequireDeviceID {
		t.Fatalf("endpoint client must be public, require PKCE and require device_id: %+v", client)
	}

	valid := []string{
		testRedirectURI,
		"https://agent.example.com/alt/callback",
		"https://AGENT.example.com/callback",
	}
	for _, redirectURI := range valid {
		if !mgr.ValidateRedirectURI(client, redirectURI) {
			t.Fatalf("ValidateRedirectURI(%q) = false, want true", redirectURI)
		}
	}

	invalid := []string{
		"http://127.0.0.1:49152/callback",
		"http://localhost:12345/callback",
		"http://evil.example:49152/callback",
		"https://agent.example.com/not-callback",
		"https://agent.example.com/callback/extra",
		"https://agent.example.com/callback#fragment",
		"https://agent.example.com/callback?next=https://evil.example/callback",
	}
	for _, redirectURI := range invalid {
		if mgr.ValidateRedirectURI(client, redirectURI) {
			t.Fatalf("ValidateRedirectURI(%q) = true, want false", redirectURI)
		}
	}
}

func TestEndpointClientRedirectValidationRejectsWildcardRegisteredURI(t *testing.T) {
	mgr := newTestOIDCManager(t)
	client := &OIDCClient{
		ClientID:     "wildcard-client",
		RedirectURIs: []string{"https://agent.example.com/alt/*"},
		Name:         "Wildcard client",
		Public:       true,
		RequirePKCE:  true,
	}

	if mgr.ValidateRedirectURI(client, "https://agent.example.com/alt/callback") {
		t.Fatalf("ValidateRedirectURI accepted redirect URI through wildcard prefix")
	}
	if mgr.ValidateRedirectURI(client, "https://agent.example.com/alt/*") {
		t.Fatalf("ValidateRedirectURI accepted a registered URI containing wildcard")
	}
}

func TestRegisterClientRejectsWildcardRedirectURI(t *testing.T) {
	mgr := newTestOIDCManager(t)
	err := mgr.RegisterClient(&OIDCClient{
		ClientID:     "wildcard-client",
		RedirectURIs: []string{"https://agent.example.com/alt/*"},
		Name:         "Wildcard client",
		Public:       true,
		RequirePKCE:  true,
	})
	if err == nil || !strings.Contains(err.Error(), "invalid redirect_uri") {
		t.Fatalf("RegisterClient() error = %v, want invalid redirect_uri", err)
	}
}

func TestExchangeCodeRequiresAndVerifiesPKCES256(t *testing.T) {
	mgr := newTestOIDCManager(t)
	registerTestEndpointClient(mgr)

	verifier := "correct-code-verifier-with-enough-entropy"
	challenge := pkceChallenge(verifier)

	sess, err := mgr.CreateAuthorizeSession(
		testEndpointClientID,
		testRedirectURI,
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

	if _, _, err := mgr.ExchangeCode(authCode.Code, testEndpointClientID, "", authCode.RedirectURI, "wrong-verifier"); err == nil || !strings.Contains(err.Error(), "PKCE") {
		t.Fatalf("ExchangeCode() with wrong verifier error = %v, want PKCE error", err)
	}

	exchanged, refreshToken, err := mgr.ExchangeCode(authCode.Code, testEndpointClientID, "", authCode.RedirectURI, verifier)
	if err != nil {
		t.Fatalf("ExchangeCode() error = %v", err)
	}
	if exchanged.DeviceID != "device-1" || exchanged.MFADone {
		t.Fatalf("exchanged code lost device/MFA state: device=%q mfa=%v", exchanged.DeviceID, exchanged.MFADone)
	}
	if refreshToken == "" {
		t.Fatal("ExchangeCode() returned empty refresh token")
	}
	refreshTokenHash := hashOIDCRefreshToken(refreshToken)
	if refreshTokenHash == refreshToken || refreshTokenHash == "" {
		t.Fatalf("refresh token hash was not derived safely: token=%q hash=%q", refreshToken, refreshTokenHash)
	}
	var storedRefresh RefreshToken
	if ok := loadOIDCState(mgr.state, oidcRefreshStateKind, refreshToken, &storedRefresh); ok {
		t.Fatalf("refresh token raw value was accepted as a state lookup key")
	}
	if ok := loadOIDCState(mgr.state, oidcRefreshStateKind, refreshTokenHash, &storedRefresh); !ok {
		t.Fatalf("refresh token hash %q was not stored", refreshTokenHash)
	}
	if storedRefresh.TokenHash != refreshTokenHash {
		t.Fatalf("stored refresh token hash = %q, want %q", storedRefresh.TokenHash, refreshTokenHash)
	}
	if storedRefresh.DeviceID != "device-1" || storedRefresh.MFADone {
		t.Fatalf("refresh token lost device/MFA state: device=%q mfa=%v", storedRefresh.DeviceID, storedRefresh.MFADone)
	}
	rawRefresh, ok := mgr.state.GetEphemeralState(oidcRefreshStateKind, refreshTokenHash)
	if !ok {
		t.Fatalf("refresh token hash state disappeared")
	}
	if strings.Contains(string(rawRefresh), refreshToken) {
		t.Fatalf("stored refresh token state contains the raw token")
	}
	if stateLister, ok := mgr.state.(interface {
		ListEphemeralState(string) (map[string][]byte, error)
	}); ok {
		states, err := stateLister.ListEphemeralState(oidcRefreshStateKind)
		if err != nil {
			t.Fatalf("list refresh token state: %v", err)
		}
		if _, exists := states[refreshToken]; exists {
			t.Fatalf("raw refresh token was used as a state key")
		}
		if _, exists := states[refreshTokenHash]; !exists {
			t.Fatalf("refresh token hash was not used as a state key")
		}
	}

	if _, _, err := mgr.ExchangeCode(authCode.Code, testEndpointClientID, "", authCode.RedirectURI, verifier); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("ExchangeCode() replay error = %v, want already used", err)
	}

	rotatedRefresh, rotatedToken, err := mgr.RefreshAccessToken(refreshToken, testEndpointClientID, "")
	if err != nil {
		t.Fatalf("RefreshAccessToken() error = %v", err)
	}
	rotatedHash := hashOIDCRefreshToken(rotatedToken)
	if rotatedRefresh.TokenHash != rotatedHash {
		t.Fatalf("rotated refresh token hash = %q, want %q", rotatedRefresh.TokenHash, rotatedHash)
	}
	if ok := loadOIDCState(mgr.state, oidcRefreshStateKind, rotatedToken, &storedRefresh); ok {
		t.Fatalf("rotated refresh token raw value was accepted as a state lookup key")
	}
	rawRotated, ok := mgr.state.GetEphemeralState(oidcRefreshStateKind, rotatedHash)
	if !ok {
		t.Fatalf("rotated refresh token hash state was not stored")
	}
	if strings.Contains(string(rawRotated), rotatedToken) {
		t.Fatalf("rotated refresh token state contains the raw token")
	}
	if _, _, err := mgr.RefreshAccessToken(refreshToken, testEndpointClientID, ""); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("RefreshAccessToken() replay error = %v, want already used", err)
	}
}

func TestExchangeCodeRejectsMissingPKCEChallenge(t *testing.T) {
	mgr := newTestOIDCManager(t)
	registerTestEndpointClient(mgr)

	sess, err := mgr.CreateAuthorizeSession(
		testEndpointClientID,
		testRedirectURI,
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

	if _, _, err := mgr.ExchangeCode(authCode.Code, testEndpointClientID, "", authCode.RedirectURI, "verifier"); err == nil || !strings.Contains(err.Error(), "code_challenge") {
		t.Fatalf("ExchangeCode() error = %v, want missing code_challenge", err)
	}
}

func registerTestEndpointClient(mgr *OIDCManager) {
	if err := mgr.RegisterClient(&OIDCClient{
		ClientID:        testEndpointClientID,
		RedirectURIs:    []string{testRedirectURI, "https://agent.example.com/alt/callback"},
		Name:            "TrustAgent endpoint",
		Public:          true,
		RequirePKCE:     true,
		RequireDeviceID: true,
	}); err != nil {
		panic(err)
	}
}

func newTestOIDCManager(t *testing.T) *OIDCManager {
	return NewOIDCManager(testredis.NewClient(t), newOIDCClientTestStore(), 5*time.Minute, time.Minute, 24*time.Hour, 30*time.Second)
}

func pkceChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

type oidcClientTestStore struct {
	mu      sync.RWMutex
	clients map[string]*models.OIDCClient
}

func newOIDCClientTestStore() *oidcClientTestStore {
	return &oidcClientTestStore{clients: map[string]*models.OIDCClient{}}
}

func (s *oidcClientTestStore) SaveOIDCClient(client *models.OIDCClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copied := *client
	copied.RedirectURIs = append([]string(nil), client.RedirectURIs...)
	s.clients[client.ClientID] = &copied
	return nil
}

func (s *oidcClientTestStore) GetOIDCClient(clientID string) (*models.OIDCClient, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	client, ok := s.clients[clientID]
	if !ok {
		return nil, false
	}
	copied := *client
	copied.RedirectURIs = append([]string(nil), client.RedirectURIs...)
	return &copied, true
}
