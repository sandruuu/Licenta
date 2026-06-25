package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"pdp/models"

	"github.com/golang-jwt/jwt/v5"
)

func TestFederationDiscoverRejectsIssuerMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		writeTestJSON(t, w, map[string]string{
			"issuer":                 "https://unexpected.example.test",
			"authorization_endpoint": "https://unexpected.example.test/auth",
			"token_endpoint":         "https://unexpected.example.test/token",
		})
	}))
	defer server.Close()

	fp := NewFederationProvider(newFederationTestState(), "openid", nil, time.Minute, time.Second)
	_, err := fp.Discover(server.URL)
	if err == nil || !strings.Contains(err.Error(), "issuer mismatch") {
		t.Fatalf("Discover() error = %v, want issuer mismatch", err)
	}
}

func TestGenerateExternalAuthURLIncludesPromptWhenConfigured(t *testing.T) {
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		writeTestJSON(t, w, map[string]string{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/auth",
			"token_endpoint":         issuer + "/token",
		})
	}))
	defer server.Close()
	issuer = server.URL

	fp := NewFederationProvider(newFederationTestState(), "openid profile email", nil, time.Minute, time.Second)
	authURL, err := fp.GenerateExternalAuthURL(&models.FederationConfig{
		Issuer:       issuer,
		ClientID:     "trustcloud",
		Prompt:       "login",
		ClaimMapping: map[string]string{},
	}, "https://pdp.example.test/callback", "state-1", "nonce-1", "challenge-1")
	if err != nil {
		t.Fatalf("GenerateExternalAuthURL() error = %v", err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Parse auth URL: %v", err)
	}
	if got := parsed.Query().Get("prompt"); got != "login" {
		t.Fatalf("prompt = %q, want login; url=%s", got, authURL)
	}
}

func TestValidateAndMapExternalClaimsVerifiesIDTokenSignature(t *testing.T) {
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}

	keyID := "sig-1"
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeTestJSON(t, w, map[string]string{
				"issuer":                 issuer,
				"authorization_endpoint": issuer + "/auth",
				"token_endpoint":         issuer + "/token",
				"jwks_uri":               issuer + "/jwks",
			})
		case "/jwks":
			writeTestJSON(t, w, JWKS{Keys: []JWK{rsaTestJWK(keyID, &signingKey.PublicKey)}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuer = server.URL

	fp := NewFederationProvider(newFederationTestState(), "openid profile email", map[string]string{
		"username": "preferred_username",
		"email":    "email",
		"groups":   "groups",
	}, time.Minute, time.Second)
	fedCfg := &models.FederationConfig{Issuer: issuer, ClientID: "trustcloud"}

	idToken := signTestIDToken(t, signingKey, keyID, issuer, "trustcloud", "nonce-1")
	claims, err := fp.ValidateAndMapExternalClaims(fedCfg, idToken, "nonce-1", nil)
	if err != nil {
		t.Fatalf("ValidateAndMapExternalClaims() error = %v", err)
	}
	if claims.Subject != "user-1" || claims.Username != "alice" || claims.Email != "alice@example.test" {
		t.Fatalf("unexpected mapped claims: %+v", claims)
	}

	badToken := signTestIDToken(t, wrongKey, keyID, issuer, "trustcloud", "nonce-1")
	if _, err := fp.ValidateAndMapExternalClaims(fedCfg, badToken, "nonce-1", nil); err == nil {
		t.Fatal("ValidateAndMapExternalClaims() accepted token signed by unknown key")
	}
}

func TestExchangeExternalCodeRequiresClientSecret(t *testing.T) {
	fp := NewFederationProvider(newFederationTestState(), "openid", nil, time.Minute, time.Second)
	_, err := fp.ExchangeExternalCode(&models.FederationConfig{
		Issuer:   "https://idp.example.test",
		ClientID: "trustcloud",
	}, "code-1", "https://pdp.example.test/callback", "verifier-1")
	if err == nil || !strings.Contains(err.Error(), "client_secret") {
		t.Fatalf("ExchangeExternalCode() error = %v, want client_secret requirement", err)
	}
}

type federationTestState struct {
	values map[string][]byte
}

func newFederationTestState() *federationTestState {
	return &federationTestState{values: map[string][]byte{}}
}

func (s *federationTestState) SaveEphemeralState(kind, key string, value []byte, _ time.Time) error {
	s.values[kind+":"+key] = append([]byte(nil), value...)
	return nil
}

func (s *federationTestState) GetEphemeralState(kind, key string) ([]byte, bool) {
	value, ok := s.values[kind+":"+key]
	return append([]byte(nil), value...), ok
}

func (s *federationTestState) DeleteEphemeralState(kind, key string) error {
	delete(s.values, kind+":"+key)
	return nil
}

func rsaTestJWK(kid string, key *rsa.PublicKey) JWK {
	return JWK{
		Kid: kid,
		Kty: "RSA",
		Alg: "RS256",
		Use: "sig",
		N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func signTestIDToken(t *testing.T, key *rsa.PrivateKey, kid, issuer, audience, nonce string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":                issuer,
		"aud":                audience,
		"sub":                "user-1",
		"preferred_username": "alice",
		"email":              "alice@example.test",
		"groups":             []string{"TrustCloud-Users"},
		"nonce":              nonce,
		"exp":                time.Now().Add(time.Hour).Unix(),
		"iat":                time.Now().Unix(),
	})
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign id_token: %v", err)
	}
	return signed
}

func writeTestJSON(t *testing.T, w http.ResponseWriter, value interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("write json: %v", err)
	}
}
