package models

import "time"

// Gateway represents a registered gateway.
type Gateway struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	FQDN            string   `json:"fqdn"`
	OrganizationID  string   `json:"organization_id,omitempty"`
	OrganizationIDs []string `json:"organization_ids,omitempty"`

	EnrollmentToken string `json:"enrollment_token,omitempty"`
	TokenExpiresAt  string `json:"token_expires_at,omitempty"`
	Status          string `json:"status"`

	CertPEM         string `json:"cert_pem,omitempty"`
	CertFingerprint string `json:"cert_fingerprint,omitempty"`
	CertSerial      string `json:"cert_serial,omitempty"`
	CertExpiresAt   string `json:"cert_expires_at,omitempty"`

	ListenAddr string `json:"listen_addr,omitempty"`
	PublicIP   string `json:"public_ip,omitempty"`

	AssignedResources []string `json:"assigned_resources,omitempty"`

	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	LastSeenAt time.Time `json:"last_seen_at,omitempty"`
}

// GatewayEnrollRequest is sent by the gateway during enrollment.
type GatewayEnrollRequest struct {
	Token  string `json:"token"`
	CSRPEM string `json:"csr_pem"`
}

// GatewayEnrollResponse is returned after successful enrollment.
type GatewayEnrollResponse struct {
	Status         string `json:"status"`
	GatewayID      string `json:"gateway_id"`
	OrganizationID string `json:"organization_id,omitempty"`
	CertPEM        string `json:"cert_pem"`
	CAPEM          string `json:"ca_pem"`
	Message        string `json:"message,omitempty"`
}
