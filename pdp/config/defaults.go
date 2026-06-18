package config

import "time"

// ApplyDefaults fills defensive defaults for zero-value runtime settings.
// Runtime deployments should keep these values explicit in config.json.
func (c *Config) ApplyDefaults() {
	if c == nil {
		return
	}
	if c.Runtime.EventBufferSize <= 0 {
		c.Runtime.EventBufferSize = 64
	}
	if c.Runtime.CatalogTTLSeconds <= 0 {
		c.Runtime.CatalogTTLSeconds = 300
	}
	if c.Runtime.PKIRenewCheckInterval <= 0 {
		c.Runtime.PKIRenewCheckInterval = 6 * time.Hour
	}
	if c.Runtime.EnrollmentCleanupInterval <= 0 {
		c.Runtime.EnrollmentCleanupInterval = time.Minute
	}
	if c.Runtime.OIDCEnrollmentTokenTTL <= 0 {
		c.Runtime.OIDCEnrollmentTokenTTL = 5 * time.Minute
	}
	if c.Runtime.WebAuthnChallengeTTL <= 0 {
		c.Runtime.WebAuthnChallengeTTL = 5 * time.Minute
	}
	if c.Runtime.WebAuthnCleanupInterval <= 0 {
		c.Runtime.WebAuthnCleanupInterval = 2 * time.Minute
	}
	if c.Runtime.FederationCacheTTL <= 0 {
		c.Runtime.FederationCacheTTL = 6 * time.Hour
	}
	if c.Runtime.FederationHTTPTimeout <= 0 {
		c.Runtime.FederationHTTPTimeout = 10 * time.Second
	}
	if c.Runtime.BrowserAuthSessionTTL <= 0 {
		c.Runtime.BrowserAuthSessionTTL = 5 * time.Minute
	}
	if c.Runtime.AdminAccessTokenTTL <= 0 {
		c.Runtime.AdminAccessTokenTTL = 5 * time.Minute
	}
	if c.Runtime.AdminSessionIdleTTL <= 0 {
		c.Runtime.AdminSessionIdleTTL = 30 * time.Minute
	}
	if c.Runtime.AdminSessionAbsoluteTTL <= 0 {
		c.Runtime.AdminSessionAbsoluteTTL = 8 * time.Hour
	}
	if c.Runtime.AgentSessionAccessTokenTTL <= 0 {
		c.Runtime.AgentSessionAccessTokenTTL = 5 * time.Minute
	}
	if c.Runtime.AgentSessionIdleTTL <= 0 {
		c.Runtime.AgentSessionIdleTTL = 30 * time.Minute
	}
	if c.Runtime.AgentSessionAbsoluteTTL <= 0 {
		c.Runtime.AgentSessionAbsoluteTTL = 8 * time.Hour
	}
	if c.Runtime.CSRFCookieMaxAgeSeconds <= 0 {
		c.Runtime.CSRFCookieMaxAgeSeconds = 3600
	}
	if c.Runtime.EnrollRateLimitWindow <= 0 {
		c.Runtime.EnrollRateLimitWindow = time.Minute
	}
	if c.Runtime.EnrollRateLimitMax <= 0 {
		c.Runtime.EnrollRateLimitMax = 5
	}
	if c.Runtime.GatewayRevokeTimeout <= 0 {
		c.Runtime.GatewayRevokeTimeout = 5 * time.Second
	}
	if c.Runtime.ResourceSessionRenewBefore <= 0 {
		c.Runtime.ResourceSessionRenewBefore = time.Minute
	}
	if c.Runtime.HTTPShutdownTimeout <= 0 {
		c.Runtime.HTTPShutdownTimeout = 15 * time.Second
	}
	if c.Runtime.ReadinessDrainDelay <= 0 {
		c.Runtime.ReadinessDrainDelay = 5 * time.Second
	}
	if c.TOTPIssuer == "" {
		c.TOTPIssuer = "TrustCloud"
	}
	if c.MFATransitKey == "" {
		if c.JWTTransitKey != "" {
			c.MFATransitKey = c.JWTTransitKey
		} else {
			c.MFATransitKey = c.PKITransitKey
		}
	}
	if c.MFASecretKeyEncryptedPath == "" && c.DataDir != "" {
		c.MFASecretKeyEncryptedPath = c.DataDir + "/mfa_secret.key.enc"
	}
	if c.Gateway.CertificateValidityDays <= 0 {
		c.Gateway.CertificateValidityDays = 7
	}
	if c.Gateway.EnrollmentTokenTTL <= 0 {
		c.Gateway.EnrollmentTokenTTL = time.Hour
	}
	if c.Enrollment.CertificateValidityDays <= 0 {
		c.Enrollment.CertificateValidityDays = 1
	}
	if c.Enrollment.BrowserSessionTTL <= 0 {
		c.Enrollment.BrowserSessionTTL = 5 * time.Minute
	}
	if c.Geo.ProviderURL == "" {
		c.Geo.ProviderURL = "https://ipapi.co/{ip}/json/"
	}
	if c.Geo.HTTPTimeout <= 0 {
		c.Geo.HTTPTimeout = 3 * time.Second
	}
	if c.Geo.CacheTTL <= 0 {
		c.Geo.CacheTTL = time.Hour
	}
	if c.Geo.CacheMaxEntries <= 0 {
		c.Geo.CacheMaxEntries = 10000
	}
	if c.Geo.SameAreaDistanceKM <= 0 {
		c.Geo.SameAreaDistanceKM = 50
	}
	if c.Geo.SuspiciousTravelSpeedKMH <= 0 {
		c.Geo.SuspiciousTravelSpeedKMH = 500
	}
	if c.Geo.ImpossibleTravelSpeedKMH <= 0 {
		c.Geo.ImpossibleTravelSpeedKMH = 900
	}
}
