package app

import "testing"

func TestParseDefaultsToBootstrap(t *testing.T) {
	options, err := Parse(nil)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if options.Command != CommandBootstrap {
		t.Fatalf("command = %q, want %q", options.Command, CommandBootstrap)
	}
}

func TestParseTrayOptions(t *testing.T) {
	options, err := Parse([]string{"tray", "--demo-message", "hello", "--stay", "--login", "--cloud-url", "https://cloud.example", "--device-id", "device-1", "--enrollment-nonce", "nonce-1"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if options.Command != CommandTray || options.DemoMessage != "hello" || !options.TrayStay || !options.Login || options.CloudURL != "https://cloud.example" || options.DeviceID != "device-1" || options.EnrollmentNonce != "nonce-1" {
		t.Fatalf("options = %+v", options)
	}
}

func TestParseBootstrapEnrollmentOptions(t *testing.T) {
	options, err := Parse([]string{"bootstrap", "--login", "--cloud-url", "https://cloud.example", "--issuer-url", "https://cloud.example", "--cloud-issuer", "https://cloud.example", "--jwks-url", "https://cloud.example/.well-known/jwks.json", "--ca-file", "ca.pem"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if options.Command != CommandBootstrap || !options.Login || options.CloudURL != "https://cloud.example" || options.IssuerURL != "https://cloud.example" || options.CloudIssuer != "https://cloud.example" || options.JWKSURL == "" || options.CAFile != "ca.pem" {
		t.Fatalf("options = %+v", options)
	}
}

func TestParseBootstrapTUNOptions(t *testing.T) {
	options, err := Parse([]string{"bootstrap", "--tun", "--tun-name", "ZTNA-Test", "--tun-ip", "100.64.0.9", "--tun-netmask", "255.192.0.0", "--tun-route-cidr", "100.64.0.0/10"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if options.Command != CommandBootstrap || !options.TUNEnabled || options.TUNName != "ZTNA-Test" || options.TUNIP != "100.64.0.9" || options.TUNNetmask != "255.192.0.0" || options.TUNRouteCIDR != "100.64.0.0/10" {
		t.Fatalf("options = %+v", options)
	}
}

func TestParseBootstrapGatewayTunnelOptions(t *testing.T) {
	options, err := Parse([]string{"bootstrap", "--gateway-tunnel", "--gateway-address", "gateway.example:9443", "--gateway-server-name", "gateway.example", "--process-identity"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if options.Command != CommandBootstrap || !options.GatewayTunnel || options.GatewayAddress != "gateway.example:9443" || options.GatewayServerName != "gateway.example" || !options.ProcessIdentity {
		t.Fatalf("options = %+v", options)
	}
}

func TestParseServiceEnrollmentVerificationOptions(t *testing.T) {
	options, err := Parse([]string{"service", "--authorized-user-sid", "S-1-5-21-1", "--cloud-issuer", "https://cloud.example", "--cloud-url", "https://cloud.example", "--jwks-url", "https://cloud.example/.well-known/jwks.json", "--ca-file", "ca.pem"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if options.Command != CommandService || options.CloudIssuer != "https://cloud.example" || options.CloudURL != "https://cloud.example" || options.JWKSURL == "" || options.CAFile != "ca.pem" {
		t.Fatalf("options = %+v", options)
	}
}

func TestParseAuthorizedSID(t *testing.T) {
	options, err := Parse([]string{"service", "--authorized-user-sid", "S-1-5-21-1"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if options.Command != CommandService || options.AuthorizedUserSID != "S-1-5-21-1" {
		t.Fatalf("options = %+v", options)
	}
}

func TestParseRejectsUnknown(t *testing.T) {
	if _, err := Parse([]string{"wat"}); err == nil {
		t.Fatalf("expected unknown command error")
	}
}
