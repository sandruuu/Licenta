package mfa

import (
	"encoding/json"
	"testing"
	"time"

	"pdp/config"
	"pdp/models"
)

func TestBeginRegistrationRequestsDiscoverablePasskey(t *testing.T) {
	provider := NewWebAuthnProvider(&config.Config{
		WebAuthnRPID:      "localhost",
		WebAuthnRPName:    "TrustCloud",
		WebAuthnRPOrigins: "https://localhost:8443",
		Runtime: config.RuntimeConfig{
			WebAuthnChallengeTTL:    5 * time.Minute,
			WebAuthnCleanupInterval: time.Hour,
		},
	})
	if provider == nil {
		t.Fatal("WebAuthn provider was not created")
	}

	options, err := provider.BeginRegistration(&models.User{
		ID:       "user-1",
		Username: "alice@example.test",
	}, nil, "challenge-1")
	if err != nil {
		t.Fatalf("BeginRegistration() error = %v", err)
	}

	var payload struct {
		PublicKey struct {
			AuthenticatorSelection struct {
				RequireResidentKey *bool  `json:"requireResidentKey"`
				ResidentKey        string `json:"residentKey"`
				UserVerification   string `json:"userVerification"`
			} `json:"authenticatorSelection"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &payload); err != nil {
		t.Fatalf("registration options are not valid JSON: %v", err)
	}

	selection := payload.PublicKey.AuthenticatorSelection
	if selection.RequireResidentKey == nil || !*selection.RequireResidentKey {
		t.Fatalf("requireResidentKey = %v, want true", selection.RequireResidentKey)
	}
	if selection.ResidentKey != "required" {
		t.Fatalf("residentKey = %q, want required", selection.ResidentKey)
	}
	if selection.UserVerification != "required" {
		t.Fatalf("userVerification = %q, want required", selection.UserVerification)
	}
}
