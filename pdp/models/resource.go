package models

import "time"

// Resource represents a protected application or service managed by the PDP.
type Resource struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Description    string            `json:"description,omitempty"`
	Type           string            `json:"type"`
	Host           string            `json:"host"`
	Port           int               `json:"port"`
	ExternalURL    string            `json:"external_url,omitempty"`
	Enabled        bool              `json:"enabled"`
	Tags           []string          `json:"tags,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	OrganizationID string            `json:"organization_id,omitempty"`
	GatewayID      string            `json:"gateway_id,omitempty"`

	CertMode   string `json:"cert_mode"`
	CertPEM    string `json:"cert_pem,omitempty"`
	KeyPEM     string `json:"key_pem,omitempty"`
	CertExpiry string `json:"cert_expiry,omitempty"`
	CertDomain string `json:"cert_domain,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
