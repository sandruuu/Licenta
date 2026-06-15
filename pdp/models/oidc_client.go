package models

import "time"

// OIDCClient represents a registered OAuth/OIDC client.
type OIDCClient struct {
	ClientID        string    `json:"client_id"`
	ClientSecret    string    `json:"client_secret"`
	RedirectURIs    []string  `json:"redirect_uris"`
	Name            string    `json:"name"`
	Public          bool      `json:"public"`
	RequirePKCE     bool      `json:"require_pkce"`
	RequireDeviceID bool      `json:"require_device_id"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}
