package jwtverify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	DefaultAudience = "ztna-enrollment"
	DefaultPurpose  = "device_enrollment"
	MaxTokenBytes   = 16 << 10
)

type Options struct {
	Issuer     string
	Audience   string
	Purpose    string
	JWKSURL    string
	CAFile     string
	HTTPClient *http.Client
	Clock      func() time.Time
	Skew       time.Duration
}

type Validator struct {
	issuer     string
	audience   string
	purpose    string
	jwksURL    string
	httpClient *http.Client
	clock      func() time.Time
	skew       time.Duration

	mu    sync.RWMutex
	cache map[string]*ecdsa.PublicKey
}

type Claims struct {
	Issuer    string
	Subject   string
	Audience  []string
	ExpiresAt time.Time
	NotBefore time.Time
	IssuedAt  time.Time
	ID        string
	UserID    string
	Username  string
	Role      string
	DeviceID  string
	UserSID   string
	Purpose   string
	Nonce     string
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ,omitempty"`
}

type rawClaims struct {
	Issuer    string        `json:"iss"`
	Subject   string        `json:"sub"`
	Audience  audienceClaim `json:"aud"`
	ExpiresAt int64         `json:"exp"`
	NotBefore int64         `json:"nbf"`
	IssuedAt  int64         `json:"iat"`
	ID        string        `json:"jti"`
	UserID    string        `json:"user_id"`
	Username  string        `json:"username"`
	Role      string        `json:"role"`
	DeviceID  string        `json:"device_id"`
	UserSID   string        `json:"user_sid"`
	Purpose   string        `json:"purpose"`
	Nonce     string        `json:"nonce"`
}

type audienceClaim []string

func (claim *audienceClaim) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*claim = []string{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*claim = many
	return nil
}

func New(options Options) (*Validator, error) {
	audience := strings.TrimSpace(options.Audience)
	if audience == "" {
		audience = DefaultAudience
	}
	purpose := strings.TrimSpace(options.Purpose)
	if purpose == "" {
		purpose = DefaultPurpose
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	skew := options.Skew
	if skew <= 0 {
		skew = time.Minute
	}
	httpClient := options.HTTPClient
	if httpClient == nil {
		client, err := buildHTTPClient(options.CAFile)
		if err != nil {
			return nil, err
		}
		httpClient = client
	}
	return &Validator{
		issuer:     strings.TrimSpace(options.Issuer),
		audience:   audience,
		purpose:    purpose,
		jwksURL:    strings.TrimSpace(options.JWKSURL),
		httpClient: httpClient,
		clock:      clock,
		skew:       skew,
		cache:      make(map[string]*ecdsa.PublicKey),
	}, nil
}

func (validator *Validator) Validate(ctx context.Context, token string) (*Claims, error) {
	if validator == nil {
		return nil, errors.New("jwt validator is nil")
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("token is required")
	}
	if len(token) > MaxTokenBytes {
		return nil, fmt.Errorf("token exceeds %d bytes", MaxTokenBytes)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("token must be a compact JWT")
	}
	headerBytes, err := decodeSegment(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode token header: %w", err)
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("decode token header JSON: %w", err)
	}
	if header.Alg != "ES256" {
		return nil, fmt.Errorf("unsupported JWT alg %q", header.Alg)
	}
	if strings.TrimSpace(header.Kid) == "" {
		return nil, errors.New("JWT kid is required")
	}
	claimsBytes, err := decodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode token claims: %w", err)
	}
	var raw rawClaims
	if err := json.Unmarshal(claimsBytes, &raw); err != nil {
		return nil, fmt.Errorf("decode token claims JSON: %w", err)
	}
	key, err := validator.key(ctx, header.Kid)
	if err != nil {
		return nil, err
	}
	if err := verifyES256(key, parts[0]+"."+parts[1], parts[2]); err != nil {
		return nil, err
	}
	claims := raw.toClaims()
	if err := validator.validateClaims(claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func (raw rawClaims) toClaims() *Claims {
	claims := &Claims{
		Issuer:   raw.Issuer,
		Subject:  raw.Subject,
		Audience: append([]string(nil), raw.Audience...),
		ID:       raw.ID,
		UserID:   raw.UserID,
		Username: raw.Username,
		Role:     raw.Role,
		DeviceID: raw.DeviceID,
		UserSID:  raw.UserSID,
		Purpose:  raw.Purpose,
		Nonce:    raw.Nonce,
	}
	if raw.ExpiresAt > 0 {
		claims.ExpiresAt = time.Unix(raw.ExpiresAt, 0).UTC()
	}
	if raw.NotBefore > 0 {
		claims.NotBefore = time.Unix(raw.NotBefore, 0).UTC()
	}
	if raw.IssuedAt > 0 {
		claims.IssuedAt = time.Unix(raw.IssuedAt, 0).UTC()
	}
	return claims
}

func (validator *Validator) validateClaims(claims *Claims) error {
	now := validator.clock().UTC()
	if validator.issuer != "" && claims.Issuer != validator.issuer {
		return fmt.Errorf("issuer mismatch")
	}
	if !contains(claims.Audience, validator.audience) {
		return fmt.Errorf("audience %v does not include %q", claims.Audience, validator.audience)
	}
	if claims.Purpose != validator.purpose {
		return fmt.Errorf("purpose mismatch")
	}
	if claims.DeviceID == "" {
		return errors.New("device_id claim is required")
	}
	if claims.ID == "" {
		return errors.New("jti claim is required")
	}
	if claims.ExpiresAt.IsZero() || !claims.ExpiresAt.After(now.Add(-validator.skew)) {
		return errors.New("token is expired")
	}
	if !claims.NotBefore.IsZero() && claims.NotBefore.After(now.Add(validator.skew)) {
		return errors.New("token is not valid yet")
	}
	if !claims.IssuedAt.IsZero() && claims.IssuedAt.After(now.Add(validator.skew)) {
		return errors.New("token issued-at is in the future")
	}
	return nil
}

func (validator *Validator) key(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	validator.mu.RLock()
	key := validator.cache[kid]
	validator.mu.RUnlock()
	if key != nil {
		return key, nil
	}
	if strings.TrimSpace(validator.jwksURL) == "" {
		return nil, errors.New("JWKS URL is required")
	}
	if err := validator.refresh(ctx); err != nil {
		return nil, err
	}
	validator.mu.RLock()
	key = validator.cache[kid]
	validator.mu.RUnlock()
	if key == nil {
		return nil, fmt.Errorf("JWKS key %q not found", kid)
	}
	return key, nil
}

func (validator *Validator) refresh(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, validator.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("build JWKS request: %w", err)
	}
	response, err := validator.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch JWKS: status %d", response.StatusCode)
	}
	var set jwksSet
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&set); err != nil {
		return fmt.Errorf("decode JWKS: %w", err)
	}
	keys := make(map[string]*ecdsa.PublicKey)
	for _, jwk := range set.Keys {
		key, err := jwk.ecdsaKey()
		if err != nil {
			continue
		}
		keys[jwk.Kid] = key
	}
	validator.mu.Lock()
	for kid, key := range keys {
		validator.cache[kid] = key
	}
	validator.mu.Unlock()
	return nil
}

type jwksSet struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
}

func (jwk jwkKey) ecdsaKey() (*ecdsa.PublicKey, error) {
	if jwk.Kid == "" || jwk.Kty != "EC" || jwk.Crv != "P-256" {
		return nil, errors.New("not an EC P-256 key")
	}
	if jwk.Alg != "" && jwk.Alg != "ES256" {
		return nil, errors.New("unsupported JWK alg")
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, err
	}
	key := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, errors.New("JWK point is not on P-256")
	}
	return key, nil
}

func verifyES256(key *ecdsa.PublicKey, signingInput, encodedSignature string) error {
	signature, err := decodeSegment(encodedSignature)
	if err != nil {
		return fmt.Errorf("decode JWT signature: %w", err)
	}
	if len(signature) != 64 {
		return fmt.Errorf("ES256 signature has %d bytes", len(signature))
	}
	digest := sha256.Sum256([]byte(signingInput))
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(key, digest[:], r, s) {
		return errors.New("JWT signature verification failed")
	}
	return nil
}

func decodeSegment(segment string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(segment)
}

func buildHTTPClient(caFile string) (*http.Client, error) {
	if strings.TrimSpace(caFile) == "" {
		return http.DefaultClient, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("CA file does not contain PEM certificates")
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}}}, nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
