package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"pdp/models"

	"github.com/golang-jwt/jwt/v5"
)

// FederationProvider handles external OIDC IdP interactions.
// It caches OIDC discovery metadata per issuer and provides
// methods to generate authorization URLs and exchange codes.
type FederationProvider struct {
	state               FederationCacheStore
	defaultScopes       string
	defaultClaimMapping map[string]string
	cacheTTL            time.Duration
	httpTimeout         time.Duration
}

type discoveryCache struct {
	Metadata  *OIDCDiscovery `json:"metadata"`
	FetchedAt time.Time      `json:"fetched_at"`
}

type FederationCacheStore interface {
	SaveEphemeralState(kind, key string, value []byte, expiresAt time.Time) error
	GetEphemeralState(kind, key string) ([]byte, bool)
	DeleteEphemeralState(kind, key string) error
}

const federationDiscoveryStateKind = "federation_discovery"

// OIDCDiscovery represents the relevant fields from .well-known/openid-configuration.
type OIDCDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// FederationSession tracks an in-flight federated authentication.
type FederationSession struct {
	ID             string    `json:"id"`
	OIDCSessionID  string    `json:"oidc_session_id"` // the PDP OIDC session this federation belongs to
	GatewayID      string    `json:"gateway_id"`
	OrganizationID string    `json:"organization_id"` // which organization's IdP is being used
	IdPID          string    `json:"idp_config_id"`   // which IdentityProviderConfig
	Issuer         string    `json:"issuer"`
	PKCEVerifier   string    `json:"pkce_verifier"`
	Nonce          string    `json:"nonce"`
	State          string    `json:"state"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// FederatedTokenResponse is the external IdP's token endpoint response.
type FederatedTokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// FederatedClaims are the identity claims extracted from the external id_token.
type FederatedClaims struct {
	Subject  string   `json:"sub"`
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Groups   []string `json:"groups"` // external IdP group memberships
}

// NewFederationProvider creates a provider that stores discovery cache in runtime state.
func NewFederationProvider(state FederationCacheStore, defaultScopes string, defaultClaimMapping map[string]string, durations ...time.Duration) *FederationProvider {
	cacheTTL := 6 * time.Hour
	httpTimeout := 10 * time.Second
	if len(durations) > 0 && durations[0] > 0 {
		cacheTTL = durations[0]
	}
	if len(durations) > 1 && durations[1] > 0 {
		httpTimeout = durations[1]
	}
	return &FederationProvider{
		state:               state,
		defaultScopes:       strings.TrimSpace(defaultScopes),
		defaultClaimMapping: copyClaimMapping(defaultClaimMapping),
		cacheTTL:            cacheTTL,
		httpTimeout:         httpTimeout,
	}
}

// Discover fetches and caches the OIDC discovery document for an issuer.
// Results are cached for 6 hours.
func (fp *FederationProvider) Discover(issuer string) (*OIDCDiscovery, error) {
	if fp == nil || fp.state == nil {
		return nil, fmt.Errorf("federation runtime state is unavailable")
	}
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}
	if cached, ok := fp.cachedDiscovery(issuer); ok {
		return cached, nil
	}

	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	client := &http.Client{Timeout: fp.httpTimeout}
	resp, err := client.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery endpoint returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("read discovery body: %w", err)
	}

	var disc OIDCDiscovery
	if err := json.Unmarshal(body, &disc); err != nil {
		return nil, fmt.Errorf("parse discovery document: %w", err)
	}

	if disc.AuthorizationEndpoint == "" || disc.TokenEndpoint == "" {
		return nil, fmt.Errorf("discovery document missing required endpoints")
	}
	expectedIssuer := strings.TrimRight(strings.TrimSpace(issuer), "/")
	actualIssuer := strings.TrimRight(strings.TrimSpace(disc.Issuer), "/")
	if actualIssuer == "" || actualIssuer != expectedIssuer {
		return nil, fmt.Errorf("discovery issuer mismatch: expected %q, got %q", expectedIssuer, actualIssuer)
	}

	fp.cacheDiscovery(issuer, &disc)

	log.Printf("[FEDERATION] Discovered OIDC endpoints for %s (auth=%s, token=%s)",
		issuer, disc.AuthorizationEndpoint, disc.TokenEndpoint)
	return &disc, nil
}

func (fp *FederationProvider) cachedDiscovery(issuer string) (*OIDCDiscovery, bool) {
	raw, ok := fp.state.GetEphemeralState(federationDiscoveryStateKind, discoveryCacheKey(issuer))
	if !ok {
		return nil, false
	}
	var cached discoveryCache
	if err := json.Unmarshal(raw, &cached); err != nil || cached.Metadata == nil {
		_ = fp.state.DeleteEphemeralState(federationDiscoveryStateKind, discoveryCacheKey(issuer))
		return nil, false
	}
	if time.Since(cached.FetchedAt) >= fp.cacheTTL {
		_ = fp.state.DeleteEphemeralState(federationDiscoveryStateKind, discoveryCacheKey(issuer))
		return nil, false
	}
	return cached.Metadata, true
}

func (fp *FederationProvider) cacheDiscovery(issuer string, discovery *OIDCDiscovery) {
	if fp == nil || fp.state == nil || discovery == nil {
		return
	}
	now := time.Now().UTC()
	ttl := fp.cacheTTL
	if ttl <= 0 {
		ttl = 6 * time.Hour
	}
	raw, err := json.Marshal(discoveryCache{Metadata: discovery, FetchedAt: now})
	if err != nil {
		return
	}
	_ = fp.state.SaveEphemeralState(federationDiscoveryStateKind, discoveryCacheKey(issuer), raw, now.Add(ttl))
}

func discoveryCacheKey(issuer string) string {
	sum := sha256.Sum256([]byte(strings.TrimRight(strings.TrimSpace(issuer), "/")))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// GeneratePKCE generates a PKCE code_verifier and S256 code_challenge.
func GeneratePKCE() (verifier, challenge string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generate PKCE verifier: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge, nil
}

// GenerateExternalAuthURL builds the authorization URL for the external IdP.
func (fp *FederationProvider) GenerateExternalAuthURL(fedCfg *models.FederationConfig, redirectURI, state, nonce, codeChallenge string) (string, error) {
	disc, err := fp.Discover(fedCfg.Issuer)
	if err != nil {
		return "", err
	}

	scopes := fedCfg.Scopes
	if scopes == "" {
		scopes = fp.defaultScopes
	}

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {fedCfg.ClientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {scopes},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}
	if prompt := strings.TrimSpace(fedCfg.Prompt); prompt != "" {
		params.Set("prompt", prompt)
	}

	return disc.AuthorizationEndpoint + "?" + params.Encode(), nil
}

// ExchangeExternalCode exchanges an authorization code at the external IdP's
// token endpoint and returns the raw token response.
func (fp *FederationProvider) ExchangeExternalCode(fedCfg *models.FederationConfig, code, redirectURI, codeVerifier string) (*FederatedTokenResponse, error) {
	disc, err := fp.Discover(fedCfg.Issuer)
	if err != nil {
		return nil, err
	}

	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {fedCfg.ClientID},
		"code_verifier": {codeVerifier},
	}
	if fedCfg.ClientSecret != "" {
		data.Set("client_secret", fedCfg.ClientSecret)
	}

	client := &http.Client{Timeout: fp.httpTimeout}
	resp, err := client.PostForm(disc.TokenEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("token exchange request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp FederatedTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("parse token response: %w", err)
	}

	if tokenResp.IDToken == "" {
		return nil, fmt.Errorf("no id_token in token response")
	}

	return &tokenResp, nil
}

func (fp *FederationProvider) ValidateAndMapExternalClaims(fedCfg *models.FederationConfig, idToken, expectedNonce string, claimMapping map[string]string) (*FederatedClaims, error) {
	if fedCfg == nil {
		return nil, fmt.Errorf("federation config is required")
	}
	disc, err := fp.Discover(fedCfg.Issuer)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(disc.JWKSURI) == "" {
		return nil, fmt.Errorf("discovery document missing jwks_uri")
	}
	keySet, err := fp.fetchJWKS(disc.JWKSURI)
	if err != nil {
		return nil, err
	}
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(idToken, claims, func(token *jwt.Token) (interface{}, error) {
		alg := fmt.Sprint(token.Header["alg"])
		if !isAllowedExternalIDTokenAlg(alg) {
			return nil, fmt.Errorf("unsupported id_token alg %q", alg)
		}
		kid, _ := token.Header["kid"].(string)
		if strings.TrimSpace(kid) == "" {
			return nil, fmt.Errorf("id_token header missing kid")
		}
		return keySet.keyFor(kid, alg)
	}, jwt.WithIssuer(disc.Issuer), jwt.WithAudience(fedCfg.ClientID), jwt.WithExpirationRequired(), jwt.WithLeeway(30*time.Second))
	if err != nil {
		return nil, fmt.Errorf("validate id_token: %w", err)
	}
	if token == nil || !token.Valid {
		return nil, fmt.Errorf("id_token is invalid")
	}
	if err := validateAuthorizedParty(claims, fedCfg.ClientID); err != nil {
		return nil, err
	}
	if expectedNonce = strings.TrimSpace(expectedNonce); expectedNonce != "" {
		nonce, _ := claims["nonce"].(string)
		if nonce != expectedNonce {
			return nil, fmt.Errorf("id_token nonce mismatch")
		}
	}
	return fp.mapExternalMapClaims(claims, claimMapping)
}

func isAllowedExternalIDTokenAlg(alg string) bool {
	switch strings.TrimSpace(alg) {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512":
		return true
	default:
		return false
	}
}

func validateAuthorizedParty(claims jwt.MapClaims, clientID string) error {
	audiences := claimStringList(claims["aud"])
	if len(audiences) <= 1 {
		return nil
	}
	azp, _ := claims["azp"].(string)
	if strings.TrimSpace(azp) != strings.TrimSpace(clientID) {
		return fmt.Errorf("id_token authorized party mismatch")
	}
	return nil
}

func claimStringList(value interface{}) []string {
	switch v := value.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return nil
		}
		return []string{strings.TrimSpace(v)}
	case []string:
		values := make([]string, 0, len(v))
		for _, item := range v {
			if strings.TrimSpace(item) != "" {
				values = append(values, strings.TrimSpace(item))
			}
		}
		return values
	case []interface{}:
		values := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				values = append(values, strings.TrimSpace(s))
			}
		}
		return values
	default:
		return nil
	}
}

func (fp *FederationProvider) fetchJWKS(jwksURI string) (*JWKS, error) {
	client := &http.Client{Timeout: fp.httpTimeout}
	resp, err := client.Get(jwksURI)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks endpoint returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read jwks body: %w", err)
	}
	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}
	return &jwks, nil
}

func (set *JWKS) keyFor(kid, alg string) (interface{}, error) {
	if set == nil {
		return nil, fmt.Errorf("jwks is empty")
	}
	for _, key := range set.Keys {
		if key.Kid != kid {
			continue
		}
		switch key.Kty {
		case "RSA":
			if !strings.HasPrefix(alg, "RS") && !strings.HasPrefix(alg, "PS") {
				return nil, fmt.Errorf("unexpected alg %q for RSA key", alg)
			}
			return rsaPublicKeyFromJWK(key)
		case "EC":
			if !strings.HasPrefix(alg, "ES") {
				return nil, fmt.Errorf("unexpected alg %q for EC key", alg)
			}
			return ecPublicKeyFromJWK(key)
		default:
			return nil, fmt.Errorf("unsupported jwk kty %q", key.Kty)
		}
	}
	return nil, fmt.Errorf("jwks key %q not found", kid)
}

func rsaPublicKeyFromJWK(key JWK) (*rsa.PublicKey, error) {
	modulus, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("decode rsa modulus: %w", err)
	}
	exponentBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("decode rsa exponent: %w", err)
	}
	exponent := 0
	for _, b := range exponentBytes {
		exponent = exponent<<8 + int(b)
	}
	if exponent == 0 {
		return nil, fmt.Errorf("rsa exponent is empty")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exponent}, nil
}

func ecPublicKeyFromJWK(key JWK) (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return nil, fmt.Errorf("decode ec x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil {
		return nil, fmt.Errorf("decode ec y: %w", err)
	}
	var curve elliptic.Curve
	switch key.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported ec curve %q", key.Crv)
	}
	return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}, nil
}

// MapExternalClaims extracts identity claims from an already trusted external
// id_token. Browser callback paths should use ValidateAndMapExternalClaims.
func (fp *FederationProvider) MapExternalClaims(idToken string, claimMapping map[string]string) (*FederatedClaims, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("parse id_token: %w", err)
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}
	return fp.mapExternalMapClaims(mapClaims, claimMapping)
}

func (fp *FederationProvider) mapExternalMapClaims(mapClaims jwt.MapClaims, claimMapping map[string]string) (*FederatedClaims, error) {
	mapping := copyClaimMapping(fp.defaultClaimMapping)
	// Override with user-configured mappings
	for k, v := range claimMapping {
		if v != "" {
			mapping[k] = v
		}
	}

	claims := &FederatedClaims{}

	// Subject is always "sub"
	if sub, ok := mapClaims["sub"].(string); ok {
		claims.Subject = sub
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("external id_token missing 'sub' claim")
	}

	// Map username
	if key, ok := mapping["username"]; ok {
		if v, ok := mapClaims[key].(string); ok {
			claims.Username = v
		}
	}
	// Fallback: use sub if no username mapped
	if claims.Username == "" {
		claims.Username = claims.Subject
	}

	// Map email
	if key, ok := mapping["email"]; ok {
		if v, ok := mapClaims[key].(string); ok {
			claims.Email = v
		}
	}

	// Map groups — supports both []string and comma-separated string
	if key, ok := mapping["groups"]; ok {
		claims.Groups = extractGroups(mapClaims, key)
	}

	log.Printf("[FEDERATION] Mapped external claims: sub=%s username=%s email=%s groups=%v",
		claims.Subject, claims.Username, claims.Email, claims.Groups)

	return claims, nil
}

func copyClaimMapping(source map[string]string) map[string]string {
	mapping := make(map[string]string, len(source))
	for key, value := range source {
		if strings.TrimSpace(value) != "" {
			mapping[key] = strings.TrimSpace(value)
		}
	}
	return mapping
}

// extractGroups extracts group names from a JWT claim value. Handles both
// []interface{} (JSON array) and string (comma-separated) formats.
func extractGroups(mapClaims jwt.MapClaims, key string) []string {
	raw, ok := mapClaims[key]
	if !ok || raw == nil {
		return nil
	}

	switch v := raw.(type) {
	case []interface{}:
		groups := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				groups = append(groups, strings.TrimSpace(s))
			}
		}
		return groups
	case string:
		if strings.TrimSpace(v) == "" {
			return nil
		}
		parts := strings.Split(v, ",")
		groups := make([]string, 0, len(parts))
		for _, p := range parts {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				groups = append(groups, trimmed)
			}
		}
		return groups
	default:
		return nil
	}
}

// MapGroupsToRole applies a list of GroupRoleRules to external group names
// and returns the highest-priority internal role. Priority order:
// admin > operator > auditor > user. If no rule matches, "user" is returned.
func MapGroupsToRole(groups []string, mapping []models.GroupRoleRule) string {
	if len(groups) == 0 || len(mapping) == 0 {
		return "user"
	}

	// Priority-ordered lookup: admin first, then operator, auditor, user
	priorityOrder := []string{"admin", "operator", "auditor", "user"}

	for _, targetRole := range priorityOrder {
		for _, rule := range mapping {
			if rule.Role != targetRole {
				continue
			}
			for _, g := range groups {
				if strings.EqualFold(g, rule.GroupName) {
					return targetRole
				}
			}
		}
	}

	return "user"
}
