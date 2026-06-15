package store

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"pdp/models"
)

func (s *Store) SaveOIDCClient(client *models.OIDCClient) error {
	if client == nil {
		return fmt.Errorf("OIDC client is required")
	}
	clientID := strings.TrimSpace(client.ClientID)
	if clientID == "" {
		return fmt.Errorf("OIDC client_id is required")
	}
	now := time.Now().UTC()
	createdAt := client.CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}
	updatedAt := now
	if !client.UpdatedAt.IsZero() {
		updatedAt = client.UpdatedAt
	}
	redirectURIs := client.RedirectURIs
	if redirectURIs == nil {
		redirectURIs = []string{}
	}

	_, err := s.db.Exec(`INSERT INTO oidc_clients
		(client_id, client_secret, redirect_uris_json, name, public,
		 require_pkce, require_device_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (client_id) DO UPDATE SET
			client_secret = EXCLUDED.client_secret,
			redirect_uris_json = EXCLUDED.redirect_uris_json,
			name = EXCLUDED.name,
			public = EXCLUDED.public,
			require_pkce = EXCLUDED.require_pkce,
			require_device_id = EXCLUDED.require_device_id,
			created_at = oidc_clients.created_at,
			updated_at = EXCLUDED.updated_at`,
		clientID, client.ClientSecret, toJSON(redirectURIs), client.Name, b2i(client.Public),
		b2i(client.RequirePKCE), b2i(client.RequireDeviceID), fmtTime(createdAt), fmtTime(updatedAt))
	if err != nil {
		log.Printf("[STORE] Failed to save OIDC client %s: %v", clientID, err)
		return err
	}
	return nil
}

func (s *Store) GetOIDCClient(clientID string) (*models.OIDCClient, bool) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil, false
	}
	row := s.db.QueryRow(`SELECT client_id, client_secret, redirect_uris_json,
		name, public, require_pkce, require_device_id, created_at, updated_at
		FROM oidc_clients WHERE client_id = ?`, clientID)
	return scanOIDCClient(row)
}

func scanOIDCClient(row *sql.Row) (*models.OIDCClient, bool) {
	client := &models.OIDCClient{}
	var redirectURIsJSON, createdAt, updatedAt string
	var public, requirePKCE, requireDeviceID int
	err := row.Scan(&client.ClientID, &client.ClientSecret, &redirectURIsJSON,
		&client.Name, &public, &requirePKCE, &requireDeviceID, &createdAt, &updatedAt)
	if err != nil {
		return nil, false
	}
	client.RedirectURIs = fromJSON[[]string](redirectURIsJSON)
	if client.RedirectURIs == nil {
		client.RedirectURIs = []string{}
	}
	client.Public = i2b(public)
	client.RequirePKCE = i2b(requirePKCE)
	client.RequireDeviceID = i2b(requireDeviceID)
	client.CreatedAt = parseTime(createdAt)
	client.UpdatedAt = parseTime(updatedAt)
	return client, true
}
