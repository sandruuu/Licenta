package transport

import (
	"fmt"
	"strings"

	"pdp/models"
)

func federationConfigFromIdentityProvider(idpCfg *models.IdentityProviderConfig, claimMapping map[string]string, prompt string) (*models.FederationConfig, error) {
	if idpCfg == nil {
		return nil, fmt.Errorf("identity provider configuration is required")
	}
	issuer := strings.TrimSpace(idpCfg.Issuer)
	clientID := strings.TrimSpace(idpCfg.ClientID)
	clientSecret := strings.TrimSpace(idpCfg.ClientSecret)
	if issuer == "" || clientID == "" {
		return nil, fmt.Errorf("identity provider issuer and client_id are required")
	}
	if clientSecret == "" {
		return nil, fmt.Errorf("identity provider client_secret is required")
	}
	if claimMapping == nil {
		claimMapping = idpCfg.ClaimMapping
	}
	return &models.FederationConfig{
		Issuer:        issuer,
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		Scopes:        idpCfg.Scopes,
		Prompt:        prompt,
		AutoDiscovery: idpCfg.AutoDiscovery,
		ClaimMapping:  claimMapping,
	}, nil
}
