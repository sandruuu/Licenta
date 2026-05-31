package models

import "time"

// Resource represents a protected application or service managed by the PDP.
type Resource struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Type        string            `json:"type"`
	Host        string            `json:"host"`
	Port        int               `json:"port"`
	ExternalURL string            `json:"external_url,omitempty"`
	Enabled     bool              `json:"enabled"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	TenantID    string            `json:"tenant_id,omitempty"`
	GatewayID   string            `json:"gateway_id,omitempty"`

	// Deprecated: protected resources are not OIDC clients. These fields are
	// kept only for databases created before the resource/client split.
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`

	CertMode   string `json:"cert_mode"`
	CertPEM    string `json:"cert_pem,omitempty"`
	KeyPEM     string `json:"key_pem,omitempty"`
	CertExpiry string `json:"cert_expiry,omitempty"`
	CertDomain string `json:"cert_domain,omitempty"`

	AllowedRoles []string `json:"allowed_roles,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
