package main

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPageSize = 100
)

type config struct {
	KeycloakBaseURL      string
	KeycloakRealm        string
	KeycloakAuthRealm    string
	KeycloakClientID     string
	KeycloakClientSecret string
	KeycloakUsername     string
	KeycloakPassword     string
	PDPBaseURL           string
	PDPSCIMBaseURL       string
	PDPOrganizationID    string
	PDPSCIMToken         string
	PDPTLSSkipVerify     bool
	SyncInterval         time.Duration
	SyncOnce             bool
	DisableMissingUsers  bool
	DeleteMissingGroups  bool
	SkipServiceAccounts  bool
	PageSize             int
}

func loadConfig() (config, error) {
	cfg := config{
		KeycloakBaseURL:     strings.TrimRight(strings.TrimSpace(os.Getenv("KEYCLOAK_BASE_URL")), "/"),
		KeycloakRealm:       strings.TrimSpace(os.Getenv("KEYCLOAK_REALM")),
		KeycloakClientID:    env("KEYCLOAK_CLIENT_ID", "admin-cli"),
		KeycloakUsername:    env("KEYCLOAK_ADMIN_USERNAME", strings.TrimSpace(os.Getenv("KEYCLOAK_ADMIN"))),
		KeycloakPassword:    strings.TrimSpace(os.Getenv("KEYCLOAK_ADMIN_PASSWORD")),
		PDPBaseURL:          strings.TrimRight(strings.TrimSpace(os.Getenv("PDP_BASE_URL")), "/"),
		PDPOrganizationID:   strings.TrimSpace(os.Getenv("PDP_ORGANIZATION_ID")),
		PDPSCIMToken:        strings.TrimSpace(os.Getenv("PDP_SCIM_TOKEN")),
		PDPTLSSkipVerify:    envBool("PDP_TLS_SKIP_VERIFY", true),
		SyncInterval:        envDuration("SYNC_INTERVAL", 60*time.Second),
		SyncOnce:            envBool("SYNC_ONCE", false),
		DisableMissingUsers: envBool("DISABLE_MISSING_USERS", true),
		DeleteMissingGroups: envBool("DELETE_MISSING_GROUPS", true),
		SkipServiceAccounts: envBool("SKIP_SERVICE_ACCOUNTS", true),
		PageSize:            envInt("PAGE_SIZE", defaultPageSize),
	}
	cfg.KeycloakClientSecret = strings.TrimSpace(os.Getenv("KEYCLOAK_CLIENT_SECRET"))
	cfg.KeycloakAuthRealm = strings.TrimSpace(os.Getenv("KEYCLOAK_AUTH_REALM"))
	if cfg.KeycloakAuthRealm == "" {
		if cfg.KeycloakClientSecret != "" {
			cfg.KeycloakAuthRealm = cfg.KeycloakRealm
		} else {
			cfg.KeycloakAuthRealm = "master"
		}
	}
	cfg.PDPSCIMBaseURL = strings.TrimRight(strings.TrimSpace(os.Getenv("PDP_SCIM_BASE_URL")), "/")
	if cfg.PDPSCIMBaseURL == "" && cfg.PDPBaseURL != "" && cfg.PDPOrganizationID != "" {
		cfg.PDPSCIMBaseURL = fmt.Sprintf("%s/scim/v2/%s", cfg.PDPBaseURL, url.PathEscape(cfg.PDPOrganizationID))
	}

	var missing []string
	if cfg.KeycloakBaseURL == "" {
		missing = append(missing, "KEYCLOAK_BASE_URL")
	}
	if cfg.KeycloakRealm == "" {
		missing = append(missing, "KEYCLOAK_REALM")
	}
	if cfg.KeycloakClientID == "" {
		missing = append(missing, "KEYCLOAK_CLIENT_ID")
	}
	if cfg.KeycloakClientSecret == "" && (cfg.KeycloakUsername == "" || cfg.KeycloakPassword == "") {
		missing = append(missing, "KEYCLOAK_CLIENT_SECRET or KEYCLOAK_ADMIN_USERNAME/KEYCLOAK_ADMIN_PASSWORD")
	}
	if cfg.PDPSCIMBaseURL == "" {
		missing = append(missing, "PDP_SCIM_BASE_URL or PDP_BASE_URL/PDP_ORGANIZATION_ID")
	}
	if cfg.PDPSCIMToken == "" {
		missing = append(missing, "PDP_SCIM_TOKEN")
	}
	if cfg.SyncInterval <= 0 && !cfg.SyncOnce {
		missing = append(missing, "SYNC_INTERVAL>0 or SYNC_ONCE=true")
	}
	if cfg.PageSize <= 0 {
		cfg.PageSize = defaultPageSize
	}
	if len(missing) > 0 {
		return config{}, fmt.Errorf("missing %s", strings.Join(missing, ", "))
	}
	return cfg, nil
}

func env(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func envBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		return time.Duration(seconds) * time.Second
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}
