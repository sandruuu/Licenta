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

func TestApplyEnvironmentOverridesPAURL(t *testing.T) {
	t.Setenv(PAURLEnv, "https://mtls.trust-cloud.dev")
	cfg := &Config{PAURL: "https://pdp:8443"}
	if err := cfg.ApplyEnvironment(); err != nil {
		t.Fatalf("ApplyEnvironment() error = %v", err)
	}
	if cfg.PAURL != "https://mtls.trust-cloud.dev" {
		t.Fatalf("PAURL = %q, want https://mtls.trust-cloud.dev", cfg.PAURL)
	}
}

func TestApplyEnvironmentOverridesSessionRevalidationInterval(t *testing.T) {
	t.Setenv(SessionRevalidationIntervalEnv, "45s")
	cfg := &Config{}
	if err := cfg.ApplyEnvironment(); err != nil {
		t.Fatalf("ApplyEnvironment() error = %v", err)
	}
	if cfg.SessionRevalidationInterval != 45*time.Second {
		t.Fatalf("SessionRevalidationInterval = %s, want 45s", cfg.SessionRevalidationInterval)
	}
}

func TestValidateDefaultsSessionRevalidationInterval(t *testing.T) {
	cfg := &Config{PAURL: "https://pdp:8443", PublicEndpoint: "gateway.example.test:9443"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if cfg.SessionRevalidationInterval != 30*time.Second {
		t.Fatalf("SessionRevalidationInterval = %s, want 30s", cfg.SessionRevalidationInterval)
	}
}

func TestLoadReadsEnvironmentOnly(t *testing.T) {
	t.Setenv(PAURLEnv, "https://mtls.trust-cloud.dev")
	t.Setenv(PublicEndpointEnv, "gateway.example.test:9443")
	t.Setenv(SessionRevalidationIntervalEnv, "1m")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.PAURL != "https://mtls.trust-cloud.dev" {
		t.Fatalf("PAURL = %q", cfg.PAURL)
	}
	if cfg.PublicEndpoint != "gateway.example.test:9443" {
		t.Fatalf("PublicEndpoint = %q", cfg.PublicEndpoint)
	}
	if cfg.SessionRevalidationInterval != time.Minute {
		t.Fatalf("SessionRevalidationInterval = %s, want 1m", cfg.SessionRevalidationInterval)
	}
}
