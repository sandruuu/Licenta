package models

import "time"

// Gateway represents a registered gateway.
type Gateway struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	FQDN      string   `json:"fqdn"`
	TenantID  string   `json:"tenant_id,omitempty"`
	TenantIDs []string `json:"tenant_ids,omitempty"`

	EnrollmentToken string `json:"enrollment_token,omitempty"`
	TokenExpiresAt  string `json:"token_expires_at,omitempty"`
	Status          string `json:"status"`

	CertPEM         string `json:"cert_pem,omitempty"`
	CertFingerprint string `json:"cert_fingerprint,omitempty"`
	CertSerial      string `json:"cert_serial,omitempty"`
	CertExpiresAt   string `json:"cert_expires_at,omitempty"`

	OIDCClientID     string `json:"oidc_client_id,omitempty"`
	OIDCClientSecret string `json:"oidc_client_secret,omitempty"`

	ListenAddr string `json:"listen_addr,omitempty"`
	PublicIP   string `json:"public_ip,omitempty"`

	AssignedResources []string `json:"assigned_resources,omitempty"`

	AuthMode         string            `json:"auth_mode"`
	FederationConfig *FederationConfig `json:"federation_config,omitempty"`

	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	LastSeenAt time.Time `json:"last_seen_at,omitempty"`
}

// FederationConfig holds legacy external OIDC provider settings for a gateway.
type FederationConfig struct {
	Issuer        string            `json:"issuer"`
	ClientID      string            `json:"client_id"`
	ClientSecret  string            `json:"client_secret,omitempty"`
	Scopes        string            `json:"scopes"`
	ClaimMapping  map[string]string `json:"claim_mapping,omitempty"`
	AutoDiscovery bool              `json:"auto_discovery"`
}

// GatewayEnrollRequest is sent by the gateway during enrollment.
type GatewayEnrollRequest struct {
	Token     string `json:"token"`
	CSRPEM    string `json:"csr_pem"`
	FQDN      string `json:"fqdn"`
	Name      string `json:"name,omitempty"`
	GatewayID string `json:"gateway_id,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
}

// GatewayEnrollResponse is returned after successful enrollment.
type GatewayEnrollResponse struct {
	Status    string `json:"status"`
	GatewayID string `json:"gateway_id"`
	TenantID  string `json:"tenant_id,omitempty"`
	CertPEM   string `json:"cert_pem"`
	CAPEM     string `json:"ca_pem"`
	Message   string `json:"message,omitempty"`
}
