package config

import "testing"

func TestLoadProjectConfig(t *testing.T) {
	if _, err := LoadFromFile("../config.json"); err != nil {
		t.Fatalf("LoadFromFile failed for project config.json: %v", err)
	}
}

func TestApplyEnvironmentOverridesPublicOrigin(t *testing.T) {
	t.Setenv(PDPPublicHostEnv, "policy-admin.remote-access-demo.xyz")

	requireMFA := false
	cfg := &Config{
		WebAuthnRPID:      "localhost",
		WebAuthnRPOrigins: "https://localhost:8443",
		AdminAuth: AdminAuthConfig{
			RequireMFA: &requireMFA,
		},
		Public: PublicDashboardConfig{
			FederatedCallbackURL: "https://localhost:8443/auth/federated/callback",
		},
	}

	cfg.ApplyEnvironmentOverrides()

	if cfg.Public.FederatedCallbackURL != "https://policy-admin.remote-access-demo.xyz/auth/federated/callback" {
		t.Fatalf("FederatedCallbackURL = %q", cfg.Public.FederatedCallbackURL)
	}
	if cfg.WebAuthnRPID != "policy-admin.remote-access-demo.xyz" {
		t.Fatalf("WebAuthnRPID = %q", cfg.WebAuthnRPID)
	}
	if cfg.WebAuthnRPOrigins != "https://policy-admin.remote-access-demo.xyz" {
		t.Fatalf("WebAuthnRPOrigins = %q", cfg.WebAuthnRPOrigins)
	}
	if len(cfg.CORSOrigins) != 1 || cfg.CORSOrigins[0] != "https://policy-admin.remote-access-demo.xyz" {
		t.Fatalf("CORSOrigins = %#v", cfg.CORSOrigins)
	}
}

func TestApplyEnvironmentOverridesExplicitValues(t *testing.T) {
	t.Setenv(PDPPublicOriginEnv, "https://pa.remote-access-demo.xyz")
	t.Setenv(PDPFederatedCallbackURLEnv, "https://callbacks.remote-access-demo.xyz/cb")
	t.Setenv(PDPWebAuthnRPIDEnv, "remote-access-demo.xyz")
	t.Setenv(PDPWebAuthnRPOriginsEnv, "https://pa.remote-access-demo.xyz,https://policy-admin.remote-access-demo.xyz")
	t.Setenv(PDPCORSOriginsEnv, "https://ui.remote-access-demo.xyz, https://ops.remote-access-demo.xyz")
	t.Setenv(PDPAdminRequireMFAEnv, "true")

	requireMFA := false
	cfg := &Config{
		WebAuthnRPID: "localhost",
		AdminAuth: AdminAuthConfig{
			RequireMFA: &requireMFA,
		},
	}

	cfg.ApplyEnvironmentOverrides()

	if cfg.Public.FederatedCallbackURL != "https://callbacks.remote-access-demo.xyz/cb" {
		t.Fatalf("FederatedCallbackURL = %q", cfg.Public.FederatedCallbackURL)
	}
	if cfg.WebAuthnRPID != "remote-access-demo.xyz" {
		t.Fatalf("WebAuthnRPID = %q", cfg.WebAuthnRPID)
	}
	if cfg.WebAuthnRPOrigins != "https://pa.remote-access-demo.xyz,https://policy-admin.remote-access-demo.xyz" {
		t.Fatalf("WebAuthnRPOrigins = %q", cfg.WebAuthnRPOrigins)
	}
	if len(cfg.CORSOrigins) != 2 || cfg.CORSOrigins[0] != "https://ui.remote-access-demo.xyz" || cfg.CORSOrigins[1] != "https://ops.remote-access-demo.xyz" {
		t.Fatalf("CORSOrigins = %#v", cfg.CORSOrigins)
	}
	if cfg.AdminAuth.RequireMFA == nil || !*cfg.AdminAuth.RequireMFA {
		t.Fatalf("RequireMFA = %v", cfg.AdminAuth.RequireMFA)
	}
}

func TestApplyEnvironmentOverridesVaultPKI(t *testing.T) {
	t.Setenv(PDPPKIURLEnv, "http://10.20.40.10:8200")
	t.Setenv(PDPPKITokenEnv, "deployment-token")
	t.Setenv(PDPPKIPathEnv, "pki_prod")
	t.Setenv(PDPPKIRolePDPEnv, "pdp-role")
	t.Setenv(PDPPKIRoleDeviceEnv, "device-role")
	t.Setenv(PDPPKIRoleGatewayEnv, "gateway-role")
	t.Setenv(PDPTransitKeyEnv, "deployment-key")
	t.Setenv(PDPPKICAFileEnv, "/app/vault-ca/vault-ca.crt")
	t.Setenv(PDPPKIServerNameEnv, "vault")

	cfg := &Config{
		PKIURL:         "http://vault:8200",
		PKIToken:       "trustcloud-vault-token",
		PKIPath:        "pki_int",
		PKIRolePDP:     "trustcloud",
		PKIRoleDevice:  "trustagent",
		PKIRoleGateway: "trustgateway",
		PKITransitKey:  "trustcloud-key",
		JWTTransitKey:  "trustcloud-key",
		MFATransitKey:  "trustcloud-key",
	}

	cfg.ApplyEnvironmentOverrides()

	if cfg.PKIURL != "http://10.20.40.10:8200" {
		t.Fatalf("PKIURL = %q", cfg.PKIURL)
	}
	if cfg.PKIToken != "deployment-token" {
		t.Fatalf("PKIToken = %q", cfg.PKIToken)
	}
	if cfg.PKIPath != "pki_prod" {
		t.Fatalf("PKIPath = %q", cfg.PKIPath)
	}
	if cfg.PKIRolePDP != "pdp-role" || cfg.PKIRoleDevice != "device-role" || cfg.PKIRoleGateway != "gateway-role" {
		t.Fatalf("PKI roles = %q %q %q", cfg.PKIRolePDP, cfg.PKIRoleDevice, cfg.PKIRoleGateway)
	}
	if cfg.PKITransitKey != "deployment-key" {
		t.Fatalf("PKITransitKey = %q", cfg.PKITransitKey)
	}
	if cfg.PKICAFile != "/app/vault-ca/vault-ca.crt" {
		t.Fatalf("PKICAFile = %q", cfg.PKICAFile)
	}
	if cfg.PKIServerName != "vault" {
		t.Fatalf("PKIServerName = %q", cfg.PKIServerName)
	}
	if cfg.JWTTransitKey != "deployment-key" {
		t.Fatalf("JWTTransitKey = %q", cfg.JWTTransitKey)
	}
	if cfg.MFATransitKey != "deployment-key" {
		t.Fatalf("MFATransitKey = %q", cfg.MFATransitKey)
	}
}
