package jwtverify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidatorAcceptsCloudSignedEnrollmentToken(t *testing.T) {
	key := newTestKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jwksForKey("kid-1", &key.PublicKey))
	}))
	defer server.Close()

	now := time.Unix(1000, 0).UTC()
	token := signTestJWT(t, key, "kid-1", map[string]any{
		"iss":       "https://cloud.example",
		"sub":       "user-1",
		"aud":       []string{DefaultAudience},
		"exp":       now.Add(5 * time.Minute).Unix(),
		"nbf":       now.Add(-time.Minute).Unix(),
		"iat":       now.Unix(),
		"jti":       "jti-1",
		"user_id":   "user-1",
		"username":  "alice@example.com",
		"role":      "user",
		"device_id": "device-1",
		"user_sid":  "S-1-5-21-1",
		"purpose":   DefaultPurpose,
		"nonce":     "nonce-1",
	})
	validator, err := New(Options{Issuer: "https://cloud.example", JWKSURL: server.URL, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	claims, err := validator.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if claims.DeviceID != "device-1" || claims.UserSID != "S-1-5-21-1" || claims.Nonce != "nonce-1" {
		t.Fatalf("claims = %+v", claims)
	}
}

func TestValidatorRejectsWrongAudience(t *testing.T) {
	key := newTestKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jwksForKey("kid-1", &key.PublicKey))
	}))
	defer server.Close()
	now := time.Unix(1000, 0).UTC()
	token := signTestJWT(t, key, "kid-1", map[string]any{
		"iss":       "https://cloud.example",
		"aud":       []string{"ztna-gateway"},
		"exp":       now.Add(5 * time.Minute).Unix(),
		"jti":       "jti-1",
		"device_id": "device-1",
		"purpose":   DefaultPurpose,
	})
	validator, err := New(Options{Issuer: "https://cloud.example", JWKSURL: server.URL, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if _, err := validator.Validate(context.Background(), token); err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("Validate error = %v, want audience error", err)
	}
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	return key
}

func jwksForKey(kid string, key *ecdsa.PublicKey) map[string]any {
	return map[string]any{"keys": []map[string]string{{
		"kty": "EC",
		"crv": "P-256",
		"kid": kid,
		"alg": "ES256",
		"use": "sig",
		"x":   base64.RawURLEncoding.EncodeToString(pad32(key.X.Bytes())),
		"y":   base64.RawURLEncoding.EncodeToString(pad32(key.Y.Bytes())),
	}}}
}

func signTestJWT(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]string{"alg": "ES256", "kid": kid, "typ": "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("Marshal header returned error: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("Marshal claims returned error: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}
	signature := append(pad32(r.Bytes()), pad32(s.Bytes())...)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func pad32(value []byte) []byte {
	if len(value) >= 32 {
		return value
	}
	padded := make([]byte, 32)
	copy(padded[32-len(value):], value)
	return padded
}

var _ = big.Int{}
