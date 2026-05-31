package config

import (
	"testing"
	"time"
)

func TestValidateAcceptsPublicEndpointWithPort(t *testing.T) {
	cfg := &Config{PAURL: "https://pdp:8443", PublicEndpoint: "localhost:9443"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsPublicEndpointWithoutPort(t *testing.T) {
	cfg := &Config{PAURL: "https://pdp:8443", PublicEndpoint: "localhost"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() returned nil error")
	}
}

func TestApplyEnvironmentOverridesPublicEndpoint(t *testing.T) {
	t.Setenv(PublicEndpointEnv, "gateway.example.test:9443")
	cfg := &Config{}
	if err := cfg.ApplyEnvironment(); err != nil {
		t.Fatalf("ApplyEnvironment() error = %v", err)
	}
	if cfg.PublicEndpoint != "gateway.example.test:9443" {
		t.Fatalf("PublicEndpoint = %q, want gateway.example.test:9443", cfg.PublicEndpoint)
	}
}

func TestValidateDefaultsSessionRevalidationInterval(t *testing.T) {
	cfg := &Config{PAURL: "https://pdp:8443"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if cfg.SessionRevalidationInterval != 30*time.Second {
		t.Fatalf("SessionRevalidationInterval = %s, want 30s", cfg.SessionRevalidationInterval)
	}
}
