package models

import "time"

// Tenant represents an isolated organization.
type Tenant struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Domain      string   `json:"domain"`
	Domains     []string `json:"domains,omitempty"`
	Description string   `json:"description,omitempty"`
	Enabled     bool     `json:"enabled"`

	DefaultIdPID string `json:"default_idp_id,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// IdentityProviderConfig defines an external OIDC provider trusted by a tenant.
type IdentityProviderConfig struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Enabled  bool   `json:"enabled"`

	Domains []string `json:"domains,omitempty"`

	Issuer        string `json:"issuer"`
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret,omitempty"`
	Scopes        string `json:"scopes"`
	AutoDiscovery bool   `json:"auto_discovery"`

	ClaimMapping     map[string]string `json:"claim_mapping,omitempty"`
	GroupRoleMapping []GroupRoleRule   `json:"group_role_mapping,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// GroupRoleRule maps an external identity provider group to a local role.
type GroupRoleRule struct {
	GroupName string `json:"group_name"`
	Role      string `json:"role"`
}
