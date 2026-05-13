package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"pdp/models"

	"github.com/golang-jwt/jwt/v5"
)

// FederationProvider handles external OIDC IdP interactions.
// It caches OIDC discovery metadata per issuer and provides
// methods to generate authorization URLs and exchange codes.
type FederationProvider struct {
	mu                  sync.RWMutex
	cache               map[string]*discoveryCache
	defaultScopes       string
	defaultClaimMapping map[string]string
	cacheTTL            time.Duration
	httpTimeout         time.Duration
}

type discoveryCache struct {
	metadata  *OIDCDiscovery
	fetchedAt time.Time
}

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
	ID            string    `json:"id"`
	OIDCSessionID string    `json:"oidc_session_id"` // the PDP OIDC session this federation belongs to
	GatewayID     string    `json:"gateway_id"`
	TenantID      string    `json:"tenant_id"`     // which tenant's IdP is being used
	IdPID         string    `json:"idp_config_id"` // which IdentityProviderConfig
	Issuer        string    `json:"issuer"`
	PKCEVerifier  string    `json:"pkce_verifier"`
	Nonce         string    `json:"nonce"`
	State         string    `json:"state"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
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

// NewFederationProvider creates a new provider with an empty discovery cache.
func NewFederationProvider(defaultScopes string, defaultClaimMapping map[string]string, durations ...time.Duration) *FederationProvider {
	cacheTTL := 6 * time.Hour
	httpTimeout := 10 * time.Second
	if len(durations) > 0 && durations[0] > 0 {
		cacheTTL = durations[0]
	}
	if len(durations) > 1 && durations[1] > 0 {
		httpTimeout = durations[1]
	}
	return &FederationProvider{
		cache:               make(map[string]*discoveryCache),
		defaultScopes:       strings.TrimSpace(defaultScopes),
		defaultClaimMapping: copyClaimMapping(defaultClaimMapping),
		cacheTTL:            cacheTTL,
		httpTimeout:         httpTimeout,
	}
}

// Discover fetches and caches the OIDC discovery document for an issuer.
// Results are cached for 6 hours.
func (fp *FederationProvider) Discover(issuer string) (*OIDCDiscovery, error) {
	fp.mu.RLock()
	if cached, ok := fp.cache[issuer]; ok && time.Since(cached.fetchedAt) < fp.cacheTTL {
		fp.mu.RUnlock()
		return cached.metadata, nil
	}
	fp.mu.RUnlock()

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

	fp.mu.Lock()
	fp.cache[issuer] = &discoveryCache{
		metadata:  &disc,
		fetchedAt: time.Now(),
	}
	fp.mu.Unlock()

	log.Printf("[FEDERATION] Discovered OIDC endpoints for %s (auth=%s, token=%s)",
		issuer, disc.AuthorizationEndpoint, disc.TokenEndpoint)
	return &disc, nil
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

// MapExternalClaims extracts identity claims from the external id_token.
// It parses the JWT without signature validation (the token was received
// directly from the external IdP's token endpoint over TLS, so it is trusted).
// The claimMapping maps our field names to external claim names.
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
