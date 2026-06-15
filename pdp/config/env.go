package config

import (
	"net/url"
	"os"
	"strings"
)

const (
	PDPFQDNEnv                 = "PDP_FQDN"
	PDPTLSDNSNamesEnv          = "PDP_TLS_DNS_NAMES"
	PDPPublicHostEnv           = "PDP_PUBLIC_HOST"
	PDPPublicOriginEnv         = "PDP_PUBLIC_ORIGIN"
	PDPFederatedCallbackURLEnv = "PDP_FEDERATED_CALLBACK_URL"
	PDPWebAuthnRPIDEnv         = "PDP_WEBAUTHN_RP_ID"
	PDPWebAuthnRPOriginsEnv    = "PDP_WEBAUTHN_RP_ORIGINS"
	PDPCORSOriginsEnv          = "PDP_CORS_ORIGINS"
	PDPPKIURLEnv               = "PDP_PKI_URL"
	PDPPKITokenEnv             = "PDP_PKI_TOKEN"
	PDPPKIPathEnv              = "PDP_PKI_PATH"
	PDPPKIRolePDPEnv           = "PDP_PKI_ROLE_PDP"
	PDPPKIRoleDeviceEnv        = "PDP_PKI_ROLE_DEVICE"
	PDPPKIRoleGatewayEnv       = "PDP_PKI_ROLE_GATEWAY"
	PDPTransitKeyEnv           = "PDP_TRANSIT_KEY"
	PDPPKICAFileEnv            = "PDP_PKI_CA_FILE"
	PDPPKIServerNameEnv        = "PDP_PKI_SERVER_NAME"
	PDPDatabaseURLEnv          = "PDP_DATABASE_URL"
	PDPRedisURLEnv             = "PDP_REDIS_URL"
)

// ApplyEnvironmentOverrides lets deployment overlays publish the PDP under a
// public hostname without mutating the local lab config.json.
func (c *Config) ApplyEnvironmentOverrides() {
	if c == nil {
		return
	}
	if value := strings.TrimSpace(os.Getenv(PDPFQDNEnv)); value != "" {
		c.PDPFQDN = value
	}
	if value := strings.TrimSpace(os.Getenv(PDPTLSDNSNamesEnv)); value != "" {
		c.TLSDNSNames = splitCSV(value)
	}
	applyStringEnv(PDPPKIURLEnv, &c.PKIURL)
	applyStringEnv(PDPPKITokenEnv, &c.PKIToken)
	applyStringEnv(PDPPKIPathEnv, &c.PKIPath)
	applyStringEnv(PDPPKIRolePDPEnv, &c.PKIRolePDP)
	applyStringEnv(PDPPKIRoleDeviceEnv, &c.PKIRoleDevice)
	applyStringEnv(PDPPKIRoleGatewayEnv, &c.PKIRoleGateway)
	if value := strings.TrimSpace(os.Getenv(PDPTransitKeyEnv)); value != "" {
		c.PKITransitKey = value
		c.JWTTransitKey = value
		c.MFATransitKey = value
	}
	applyStringEnv(PDPPKICAFileEnv, &c.PKICAFile)
	applyStringEnv(PDPPKIServerNameEnv, &c.PKIServerName)
	applyStringEnv(PDPDatabaseURLEnv, &c.DatabaseURL)
	applyStringEnv(PDPRedisURLEnv, &c.RedisURL)
	if origin, rpHost := publicOriginFromEnvironment(); origin != "" {
		c.applyPublicOrigin(origin, rpHost)
	}
	if value := strings.TrimSpace(os.Getenv(PDPFederatedCallbackURLEnv)); value != "" {
		c.Public.FederatedCallbackURL = value
	}
	if value := strings.TrimSpace(os.Getenv(PDPWebAuthnRPIDEnv)); value != "" {
		c.WebAuthnRPID = value
	}
	if value := strings.TrimSpace(os.Getenv(PDPWebAuthnRPOriginsEnv)); value != "" {
		c.WebAuthnRPOrigins = value
	}
	if value := strings.TrimSpace(os.Getenv(PDPCORSOriginsEnv)); value != "" {
		c.CORSOrigins = splitCSV(value)
	}
}

func applyStringEnv(name string, target *string) {
	if target == nil {
		return
	}
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		*target = value
	}
}

func publicOriginFromEnvironment() (string, string) {
	if value := strings.TrimSpace(os.Getenv(PDPPublicOriginEnv)); value != "" {
		return normalizePublicOrigin(value)
	}
	if value := strings.TrimSpace(os.Getenv(PDPPublicHostEnv)); value != "" {
		return normalizePublicOrigin("https://" + value)
	}
	return "", ""
}

func normalizePublicOrigin(value string) (string, string) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", ""
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", ""
	}
	return parsed.Scheme + "://" + parsed.Host, parsed.Hostname()
}

func (c *Config) applyPublicOrigin(origin, rpHost string) {
	c.Public.FederatedCallbackURL = strings.TrimRight(origin, "/") + "/auth/federated/callback"
	c.WebAuthnRPOrigins = origin
	if rpHost != "" && c.WebAuthnRPID == "" {
		c.WebAuthnRPID = rpHost
	}
	c.CORSOrigins = appendUnique(c.CORSOrigins, origin)
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func appendUnique(values []string, value string) []string {
	if strings.TrimSpace(value) == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
