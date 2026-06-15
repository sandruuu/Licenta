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
	if c.Risk.DeviceDataCriticalAfter <= 0 {
		c.Risk.DeviceDataCriticalAfter = 30 * time.Minute
	}
	if c.Risk.DeviceDataStaleAfter <= 0 {
		c.Risk.DeviceDataStaleAfter = 10 * time.Minute
	}
	if c.Risk.DeviceDataCriticalPoints <= 0 {
		c.Risk.DeviceDataCriticalPoints = 30
	}
	if c.Risk.DeviceDataStalePoints <= 0 {
		c.Risk.DeviceDataStalePoints = 15
	}
	if c.Risk.NoDeviceHealthPoints <= 0 {
		c.Risk.NoDeviceHealthPoints = 25
	}
	if c.Risk.HealthExcellentMin <= 0 {
		c.Risk.HealthExcellentMin = 80
	}
	if c.Risk.HealthGoodMin <= 0 {
		c.Risk.HealthGoodMin = 60
	}
	if c.Risk.HealthFairMin <= 0 {
		c.Risk.HealthFairMin = 40
	}
	if c.Risk.HealthGoodPoints <= 0 {
		c.Risk.HealthGoodPoints = 10
	}
	if c.Risk.HealthFairPoints <= 0 {
		c.Risk.HealthFairPoints = 20
	}
	if c.Risk.HealthPoorPoints <= 0 {
		c.Risk.HealthPoorPoints = 35
	}
	if len(c.Risk.CriticalCheckPoints) == 0 {
		c.Risk.CriticalCheckPoints = map[string]int{
			"Firewall":        5,
			"Antivirus":       5,
			"Disk Encryption": 3,
			"Password & Lock": 2,
		}
	}
	if c.Risk.FailedAttemptsHigh <= 0 {
		c.Risk.FailedAttemptsHigh = 5
	}
	if c.Risk.FailedAttemptsMedium <= 0 {
		c.Risk.FailedAttemptsMedium = 3
	}
	if c.Risk.FailedAttemptsLow <= 0 {
		c.Risk.FailedAttemptsLow = 1
	}
	if c.Risk.FailedAttemptsHighPoints <= 0 {
		c.Risk.FailedAttemptsHighPoints = 20
	}
	if c.Risk.FailedAttemptsMediumPoints <= 0 {
		c.Risk.FailedAttemptsMediumPoints = 10
	}
	if c.Risk.FailedAttemptsLowPoints <= 0 {
		c.Risk.FailedAttemptsLowPoints = 5
	}
	if c.Risk.BusinessHoursEnd <= c.Risk.BusinessHoursStart {
		c.Risk.BusinessHoursStart = 8
		c.Risk.BusinessHoursEnd = 18
	}
	if len(c.Risk.BusinessDays) == 0 {
		c.Risk.BusinessDays = []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"}
	}
	if c.Risk.OutsideBusinessPoints <= 0 {
		c.Risk.OutsideBusinessPoints = 10
	}
	if c.Risk.NightHoursEnd <= c.Risk.NightHoursStart {
		c.Risk.NightHoursStart = 0
		c.Risk.NightHoursEnd = 6
	}
	if c.Risk.NightHoursPoints <= 0 {
		c.Risk.NightHoursPoints = 5
	}
	if c.Risk.NewDevicePoints <= 0 {
		c.Risk.NewDevicePoints = 10
	}
	if c.Risk.NewLocationPoints <= 0 {
		c.Risk.NewLocationPoints = 5
	}
	if c.Risk.UserBaselineAnomalyPoints <= 0 {
		c.Risk.UserBaselineAnomalyPoints = 15
	}
	if len(c.Risk.ProtocolPoints) == 0 {
		c.Risk.ProtocolPoints = map[string]int{
			"rdp":   10,
			"ssh":   5,
			"http":  0,
			"https": 0,
		}
	}
	if c.Risk.UnknownProtocolPoints <= 0 {
		c.Risk.UnknownProtocolPoints = 5
	}
	if c.Risk.ImpossibleTravelPoints <= 0 {
		c.Risk.ImpossibleTravelPoints = 30
	}
	if c.Risk.SuspiciousGeoVelocityKMH <= 0 {
		c.Risk.SuspiciousGeoVelocityKMH = 500
	}
	if c.Risk.SuspiciousGeoVelocityPoints <= 0 {
		c.Risk.SuspiciousGeoVelocityPoints = 15
	}
	if c.Risk.MaxAnomalyPoints <= 0 {
		c.Risk.MaxAnomalyPoints = 25
	}
	if c.Risk.MaxScore <= 0 {
		c.Risk.MaxScore = 100
	}
}
