package models

// FederationConfig contains the external OIDC provider settings used during
// brokered authentication exchanges.
type FederationConfig struct {
	Issuer        string            `json:"issuer"`
	ClientID      string            `json:"client_id"`
	ClientSecret  string            `json:"client_secret,omitempty"`
	Scopes        string            `json:"scopes"`
	Prompt        string            `json:"prompt,omitempty"`
	ClaimMapping  map[string]string `json:"claim_mapping,omitempty"`
	AutoDiscovery bool              `json:"auto_discovery"`
}
