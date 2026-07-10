package config

import "time"

// ApplyDefaults fills stable operational defaults so config.json only needs
// deployment-specific values.
func (c *Config) ApplyDefaults() {
	if c == nil {
		return
	}
	defaultString(&c.ListenAddr, ":8443")
	defaultString(&c.TLSCert, "/app/data/pdp-server-tls-cert.pem")
	defaultString(&c.MTLSCA, "/app/data/vault-pki-ca-cert.pem")
	defaultString(&c.DataDir, "/app/data")

	defaultString(&c.PKIPath, "pki_int")
	defaultString(&c.PKIRolePDP, "trustcloud")
	defaultString(&c.PKIRoleDevice, "trustagent")
	defaultString(&c.PKIRoleGateway, "trustgateway")
	defaultDuration(&c.PKITimeout, 10*time.Second)
	defaultString(&c.JWTTransitKey, c.PKITransitKey)

	defaultString(&c.TOTPIssuer, "TrustCloud")
	defaultString(&c.MFATransitKey, firstNonEmpty(c.JWTTransitKey, c.PKITransitKey))
	defaultString(&c.PDPKeyEncryptedPath, c.DataDir+"/pdp_key.enc")
	defaultString(&c.JWTKeyEncryptedPath, c.DataDir+"/jwt_signing_key.enc")
	defaultString(&c.MFASecretKeyEncryptedPath, c.DataDir+"/mfa_secret.key.enc")

	defaultDuration(&c.SessionExpiry, 10*time.Minute)
	defaultInt(&c.MaxSessions, 5)
	defaultInt(&c.MaxLoginAttempts, 5)
	defaultDuration(&c.LockoutDuration, 15*time.Minute)
	defaultString(&c.WebAuthnRPName, "TrustCloud")

	defaultDuration(&c.Runtime.StoreAutoSaveInterval, time.Minute)
	defaultDuration(&c.Runtime.SessionCleanupInterval, 5*time.Minute)
	defaultDuration(&c.Runtime.EnrollmentCleanupInterval, time.Minute)
	defaultDuration(&c.Runtime.CertificateRenewBefore, 24*time.Hour)
	defaultDuration(&c.Runtime.PKIRenewCheckInterval, 6*time.Hour)
	defaultDuration(&c.Runtime.HTTPReadHeaderTimeout, 10*time.Second)
	defaultDuration(&c.Runtime.HTTPShutdownTimeout, 15*time.Second)
	defaultDuration(&c.Runtime.ReadinessDrainDelay, 5*time.Second)
	defaultInt(&c.Runtime.EventBufferSize, 64)
	defaultInt(&c.Runtime.CatalogTTLSeconds, 300)
	defaultDuration(&c.Runtime.AuthRateLimitWindow, 15*time.Minute)
	defaultInt(&c.Runtime.AuthRateLimitMax, 10)
	defaultDuration(&c.Runtime.OIDCEnrollmentTokenTTL, 5*time.Minute)
	defaultDuration(&c.Runtime.WebAuthnChallengeTTL, 5*time.Minute)
	defaultDuration(&c.Runtime.WebAuthnCleanupInterval, 2*time.Minute)
	defaultDuration(&c.Runtime.FederationCacheTTL, 6*time.Hour)
	defaultDuration(&c.Runtime.FederationHTTPTimeout, 10*time.Second)
	defaultDuration(&c.Runtime.BrowserAuthSessionTTL, 5*time.Minute)
	defaultDuration(&c.Runtime.AdminAccessTokenTTL, time.Hour)
	defaultDuration(&c.Runtime.AdminSessionIdleTTL, 30*time.Minute)
	defaultDuration(&c.Runtime.AdminSessionAbsoluteTTL, 8*time.Hour)
	defaultDuration(&c.Runtime.AgentSessionAccessTokenTTL, time.Hour)
	defaultDuration(&c.Runtime.AgentSessionIdleTTL, 30*time.Minute)
	defaultDuration(&c.Runtime.AgentSessionAbsoluteTTL, 8*time.Hour)
	defaultInt(&c.Runtime.CSRFCookieMaxAgeSeconds, 3600)
	defaultDuration(&c.Runtime.EnrollRateLimitWindow, time.Minute)
	defaultInt(&c.Runtime.EnrollRateLimitMax, 5)
	defaultDuration(&c.Runtime.GatewayRevokeTimeout, 5*time.Second)
	defaultDuration(&c.Runtime.ResourceSessionRenewBefore, time.Minute)

	defaultString(&c.Public.OIDCDefaultScopes, "openid profile email")
	defaultMapEntry(&c.Public.OIDCDefaultClaimMapping, "username", "preferred_username")
	defaultMapEntry(&c.Public.OIDCDefaultClaimMapping, "email", "email")
	defaultMapEntry(&c.Public.OIDCDefaultClaimMapping, "groups", "groups")
	defaultIntMapEntry(&c.Public.ResourceDefaultPorts, "web", 443)
	defaultIntMapEntry(&c.Public.ResourceDefaultPorts, "ssh", 22)
	defaultIntMapEntry(&c.Public.ResourceDefaultPorts, "rdp", 3389)

	defaultInt(&c.Gateway.CertificateValidityDays, 7)
	defaultDuration(&c.Gateway.EnrollmentTokenTTL, time.Hour)
	defaultInt(&c.Enrollment.CertificateValidityDays, 30)
	defaultDuration(&c.Enrollment.BrowserSessionTTL, 5*time.Minute)

	defaultString(&c.Geo.ProviderURL, "https://ipapi.co/{ip}/json/")
	defaultDuration(&c.Geo.HTTPTimeout, 3*time.Second)
	defaultDuration(&c.Geo.CacheTTL, time.Hour)
	defaultInt(&c.Geo.CacheMaxEntries, 10000)
	defaultFloat(&c.Geo.SameAreaDistanceKM, 50)
	defaultFloat(&c.Geo.SuspiciousTravelSpeedKMH, 500)
	defaultFloat(&c.Geo.ImpossibleTravelSpeedKMH, 900)

	if origin, rpHost := normalizePublicOrigin(c.PublicOrigin); origin != "" {
		c.applyPublicOrigin(origin, rpHost, false)
	}
}

func defaultString(value *string, fallback string) {
	if value != nil && *value == "" && fallback != "" {
		*value = fallback
	}
}

func defaultDuration(value *time.Duration, fallback time.Duration) {
	if value != nil && *value <= 0 {
		*value = fallback
	}
}

func defaultInt(value *int, fallback int) {
	if value != nil && *value <= 0 {
		*value = fallback
	}
}

func defaultFloat(value *float64, fallback float64) {
	if value != nil && *value <= 0 {
		*value = fallback
	}
}

func defaultMapEntry(values *map[string]string, key, fallback string) {
	if *values == nil {
		*values = map[string]string{}
	}
	if (*values)[key] == "" {
		(*values)[key] = fallback
	}
}

func defaultIntMapEntry(values *map[string]int, key string, fallback int) {
	if *values == nil {
		*values = map[string]int{}
	}
	if (*values)[key] <= 0 {
		(*values)[key] = fallback
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
