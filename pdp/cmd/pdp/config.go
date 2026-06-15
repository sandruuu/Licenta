package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"pdp/config"
)

func loadConfig(path string) *config.Config {
	cfg, err := config.LoadFromFile(path)
	if err != nil {
		log.Fatalf("Failed to load config from %s: %v", path, err)
	}
	if err := validateProductionConfig(cfg); err != nil {
		log.Fatalf("Invalid production config: %v", err)
	}
	log.Printf("Config loaded from %s", path)
	return cfg
}

func validateProductionConfig(cfg *config.Config) error {
	if cfg == nil {
		return fmt.Errorf("config is required")
	}
	missing := []string{}
	for name, value := range requiredStringSettings(cfg) {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required fields: %s", strings.Join(missing, ", "))
	}
	if err := validateCertificateDNSNames(cfg.CertificateDNSNames()); err != nil {
		return err
	}

	invalid := []string{}
	for name, value := range requiredDurationSettings(cfg) {
		if value <= 0 {
			invalid = append(invalid, name)
		}
	}
	for name, value := range requiredIntegerSettings(cfg) {
		if value <= 0 {
			invalid = append(invalid, name)
		}
	}
	if len(invalid) > 0 {
		return fmt.Errorf("fields must be positive: %s", strings.Join(invalid, ", "))
	}
	return nil
}

func validateCertificateDNSNames(names []string) error {
	for _, name := range names {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "://") || strings.ContainsAny(trimmed, "/?#") {
			return fmt.Errorf("certificate DNS name %q must be a hostname or IP address, not a URL", trimmed)
		}
	}
	return nil
}

func requiredStringSettings(cfg *config.Config) map[string]string {
	return map[string]string{
		"listen_addr":                   cfg.ListenAddr,
		"pdp_fqdn":                      cfg.PDPFQDN,
		"tls_cert":                      cfg.TLSCert,
		"mtls_ca":                       cfg.MTLSCA,
		"pki_url":                       cfg.PKIURL,
		"pki_token":                     cfg.PKIToken,
		"pki_path":                      cfg.PKIPath,
		"pki_role_pdp":                  cfg.PKIRolePDP,
		"pki_role_device":               cfg.PKIRoleDevice,
		"pki_role_gateway":              cfg.PKIRoleGateway,
		"pki_transit_key":               cfg.PKITransitKey,
		"jwt_transit_key":               cfg.JWTTransitKey,
		"jwt_key_encrypted_path":        cfg.JWTKeyEncryptedPath,
		"mfa_transit_key":               cfg.MFATransitKey,
		"mfa_secret_key_encrypted_path": cfg.MFASecretKeyEncryptedPath,
		"data_dir":                      cfg.DataDir,
		"database_url":                  cfg.DatabaseURL,
		"redis_url":                     cfg.RedisURL,
		"pdp_key_encrypted_path":        cfg.PDPKeyEncryptedPath,
		"webauthn_rp_id":                cfg.WebAuthnRPID,
		"webauthn_rp_origins":           cfg.WebAuthnRPOrigins,
		"public.federated_callback_url": cfg.Public.FederatedCallbackURL,
	}
}

func requiredDurationSettings(cfg *config.Config) map[string]time.Duration {
	return map[string]time.Duration{
		"pki_timeout":                           cfg.PKITimeout,
		"jwt_expiry":                            cfg.JWTExpiry,
		"session_expiry":                        cfg.SessionExpiry,
		"lockout_duration":                      cfg.LockoutDuration,
		"runtime.store_auto_save_interval":      cfg.Runtime.StoreAutoSaveInterval,
		"runtime.session_cleanup_interval":      cfg.Runtime.SessionCleanupInterval,
		"runtime.enrollment_cleanup_interval":   cfg.Runtime.EnrollmentCleanupInterval,
		"runtime.certificate_renew_before":      cfg.Runtime.CertificateRenewBefore,
		"runtime.pki_renew_check_interval":      cfg.Runtime.PKIRenewCheckInterval,
		"runtime.http_read_header_timeout":      cfg.Runtime.HTTPReadHeaderTimeout,
		"runtime.http_shutdown_timeout":         cfg.Runtime.HTTPShutdownTimeout,
		"runtime.readiness_drain_delay":         cfg.Runtime.ReadinessDrainDelay,
		"runtime.auth_rate_limit_window":        cfg.Runtime.AuthRateLimitWindow,
		"runtime.oidc_authorize_session_ttl":    cfg.Runtime.OIDCAuthorizeSessionTTL,
		"runtime.oidc_auth_code_ttl":            cfg.Runtime.OIDCAuthCodeTTL,
		"runtime.oidc_refresh_token_ttl":        cfg.Runtime.OIDCRefreshTokenTTL,
		"runtime.oidc_cleanup_interval":         cfg.Runtime.OIDCCleanupInterval,
		"runtime.oidc_enrollment_token_ttl":     cfg.Runtime.OIDCEnrollmentTokenTTL,
		"runtime.webauthn_challenge_ttl":        cfg.Runtime.WebAuthnChallengeTTL,
		"runtime.webauthn_cleanup_interval":     cfg.Runtime.WebAuthnCleanupInterval,
		"runtime.federation_cache_ttl":          cfg.Runtime.FederationCacheTTL,
		"runtime.federation_http_timeout":       cfg.Runtime.FederationHTTPTimeout,
		"runtime.browser_auth_session_ttl":      cfg.Runtime.BrowserAuthSessionTTL,
		"runtime.enroll_rate_limit_window":      cfg.Runtime.EnrollRateLimitWindow,
		"runtime.gateway_revoke_timeout":        cfg.Runtime.GatewayRevokeTimeout,
		"runtime.resource_session_renew_before": cfg.Runtime.ResourceSessionRenewBefore,
	}
}

func requiredIntegerSettings(cfg *config.Config) map[string]int {
	return map[string]int{
		"max_sessions":                        cfg.MaxSessions,
		"max_login_attempts":                  cfg.MaxLoginAttempts,
		"runtime.event_buffer_size":           cfg.Runtime.EventBufferSize,
		"runtime.catalog_ttl_seconds":         cfg.Runtime.CatalogTTLSeconds,
		"runtime.auth_rate_limit_max":         cfg.Runtime.AuthRateLimitMax,
		"runtime.csrf_cookie_max_age_seconds": cfg.Runtime.CSRFCookieMaxAgeSeconds,
		"runtime.enroll_rate_limit_max":       cfg.Runtime.EnrollRateLimitMax,
	}
}

func ensureDataDir(cfg *config.Config) {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		log.Fatalf("Failed to create data dir %s: %v", cfg.DataDir, err)
	}
}
