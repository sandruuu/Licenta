package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"log"
	"strings"
	"time"

	"pdp/models"

	_ "modernc.org/sqlite"
)

// ─────────────────────────────────────────────
// Gateway operations
// ─────────────────────────────────────────────

func (s *Store) SaveGateway(gw *models.Gateway) {
	resources := gw.AssignedResources
	if resources == nil {
		resources = []string{}
	}
	tenantIDs := gw.TenantIDs
	if tenantIDs == nil {
		tenantIDs = []string{}
	}
	if gw.TenantID != "" && len(tenantIDs) == 0 {
		tenantIDs = []string{gw.TenantID}
	}
	authMode := gw.AuthMode
	if authMode == "" {
		authMode = "builtin"
	}
	fedConfigJSON := ""
	if gw.FederationConfig != nil {
		fedConfigJSON = toJSON(gw.FederationConfig)
	}

	_, err := s.db.Exec(`INSERT OR REPLACE INTO gateways
		(id, name, fqdn, tenant_id, tenant_ids_json, enrollment_token, token_expires_at, status,
		 cert_pem, cert_fingerprint, cert_serial, cert_expires_at,
		 oidc_client_id, oidc_client_secret, listen_addr, public_ip,
		 assigned_resources_json, auth_mode, federation_config_json,
		 created_at, updated_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		gw.ID, gw.Name, gw.FQDN, gw.TenantID, toJSON(tenantIDs),
		gw.EnrollmentToken, gw.TokenExpiresAt, gw.Status,
		gw.CertPEM, gw.CertFingerprint, gw.CertSerial, gw.CertExpiresAt,
		gw.OIDCClientID, gw.OIDCClientSecret, gw.ListenAddr, gw.PublicIP,
		toJSON(resources), authMode, fedConfigJSON,
		fmtTime(gw.CreatedAt), fmtTime(gw.UpdatedAt), fmtTime(gw.LastSeenAt))
	if err != nil {
		log.Printf("[STORE] Failed to save gateway %s: %v", gw.ID, err)
	}
}

func (s *Store) GetGateway(id string) (*models.Gateway, bool) {
	row := s.db.QueryRow(`SELECT id, name, fqdn, tenant_id, tenant_ids_json,
		enrollment_token, token_expires_at, status,
		cert_pem, cert_fingerprint, cert_serial, cert_expires_at,
		oidc_client_id, oidc_client_secret, listen_addr, public_ip,
		assigned_resources_json, auth_mode, federation_config_json,
		created_at, updated_at, last_seen_at
		FROM gateways WHERE id = ?`, id)
	return s.scanGateway(row)
}

func (s *Store) GetGatewayByToken(token string) (*models.Gateway, bool) {
	if token == "" {
		return nil, false
	}
	tokenHash := sha256Hex(token)
	return s.GetGatewayByTokenHash(tokenHash)
}

func (s *Store) GetGatewayByTokenHash(tokenHash string) (*models.Gateway, bool) {
	if tokenHash == "" {
		return nil, false
	}
	row := s.db.QueryRow(`SELECT id, name, fqdn, tenant_id, tenant_ids_json,
		enrollment_token, token_expires_at, status,
		cert_pem, cert_fingerprint, cert_serial, cert_expires_at,
		oidc_client_id, oidc_client_secret, listen_addr, public_ip,
		assigned_resources_json, auth_mode, federation_config_json,
		created_at, updated_at, last_seen_at
		FROM gateways WHERE enrollment_token = ?`, tokenHash)
	return s.scanGateway(row)
}

// ConsumeGatewayEnrollmentToken atomically consumes a pending gateway
// enrollment token. The service performs semantic validation before this call;
// the conditional update prevents concurrent replay from minting multiple
// certificates with the same token.
func (s *Store) ConsumeGatewayEnrollmentToken(gatewayID, token string, now time.Time) bool {
	gatewayID = strings.TrimSpace(gatewayID)
	token = strings.TrimSpace(token)
	if gatewayID == "" || token == "" {
		return false
	}
	result, err := s.db.Exec(`UPDATE gateways
		SET enrollment_token = '', token_expires_at = '', status = 'enrolling', updated_at = ?
		WHERE id = ? AND enrollment_token = ? AND status = 'pending'`,
		fmtTime(now), gatewayID, sha256Hex(token))
	if err != nil {
		log.Printf("[STORE] Failed to consume gateway enrollment token for %s: %v", gatewayID, err)
		return false
	}
	affected, err := result.RowsAffected()
	return err == nil && affected == 1
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func (s *Store) GetGatewayByFQDN(fqdn string) (*models.Gateway, bool) {
	if fqdn == "" {
		return nil, false
	}
	row := s.db.QueryRow(`SELECT id, name, fqdn, tenant_id, tenant_ids_json,
		enrollment_token, token_expires_at, status,
		cert_pem, cert_fingerprint, cert_serial, cert_expires_at,
		oidc_client_id, oidc_client_secret, listen_addr, public_ip,
		assigned_resources_json, auth_mode, federation_config_json,
		created_at, updated_at, last_seen_at
		FROM gateways WHERE fqdn = ?`, fqdn)
	return s.scanGateway(row)
}

func (s *Store) ListGateways() []*models.Gateway {
	rows, err := s.db.Query(`SELECT id, name, fqdn, tenant_id, tenant_ids_json,
		enrollment_token, token_expires_at, status,
		cert_pem, cert_fingerprint, cert_serial, cert_expires_at,
		oidc_client_id, oidc_client_secret, listen_addr, public_ip,
		assigned_resources_json, auth_mode, federation_config_json,
		created_at, updated_at, last_seen_at
		FROM gateways ORDER BY created_at DESC`)
	if err != nil {
		log.Printf("[STORE] Failed to list gateways: %v", err)
		return nil
	}
	defer rows.Close()

	var gateways []*models.Gateway
	for rows.Next() {
		gw := &models.Gateway{}
		var tenantIDsJSON, resourcesJSON, fedConfigJSON, createdAt, updatedAt, lastSeenAt string
		if err := rows.Scan(&gw.ID, &gw.Name, &gw.FQDN, &gw.TenantID, &tenantIDsJSON,
			&gw.EnrollmentToken, &gw.TokenExpiresAt, &gw.Status,
			&gw.CertPEM, &gw.CertFingerprint, &gw.CertSerial, &gw.CertExpiresAt,
			&gw.OIDCClientID, &gw.OIDCClientSecret, &gw.ListenAddr, &gw.PublicIP,
			&resourcesJSON, &gw.AuthMode, &fedConfigJSON, &createdAt, &updatedAt, &lastSeenAt); err != nil {
			continue
		}
		gw.TenantIDs = fromJSON[[]string](tenantIDsJSON)
		if gw.TenantIDs == nil {
			gw.TenantIDs = []string{}
		}
		if gw.TenantID == "" && len(gw.TenantIDs) == 1 {
			gw.TenantID = gw.TenantIDs[0]
		}
		gw.AssignedResources = fromJSON[[]string](resourcesJSON)
		if fedConfigJSON != "" {
			gw.FederationConfig = fromJSONPtr[models.FederationConfig](fedConfigJSON)
		}
		if gw.AuthMode == "" {
			gw.AuthMode = "builtin"
		}
		gw.CreatedAt = parseTime(createdAt)
		gw.UpdatedAt = parseTime(updatedAt)
		gw.LastSeenAt = parseTime(lastSeenAt)
		gateways = append(gateways, gw)
	}
	return gateways
}

func (s *Store) ListGatewaysByTenant(tenantID string) []*models.Gateway {
	gateways := s.ListGateways()
	filtered := make([]*models.Gateway, 0, len(gateways))
	for _, gateway := range gateways {
		if gateway == nil {
			continue
		}
		if strings.TrimSpace(gateway.TenantID) == strings.TrimSpace(tenantID) {
			filtered = append(filtered, gateway)
		}
	}
	return filtered
}

func (s *Store) DeleteGateway(id string) bool {
	result, err := s.db.Exec("DELETE FROM gateways WHERE id = ?", id)
	if err != nil {
		return false
	}
	n, _ := result.RowsAffected()
	return n > 0
}

func (s *Store) scanGateway(row *sql.Row) (*models.Gateway, bool) {
	gw := &models.Gateway{}
	var tenantIDsJSON, resourcesJSON, fedConfigJSON, createdAt, updatedAt, lastSeenAt string
	err := row.Scan(&gw.ID, &gw.Name, &gw.FQDN, &gw.TenantID, &tenantIDsJSON,
		&gw.EnrollmentToken, &gw.TokenExpiresAt, &gw.Status,
		&gw.CertPEM, &gw.CertFingerprint, &gw.CertSerial, &gw.CertExpiresAt,
		&gw.OIDCClientID, &gw.OIDCClientSecret, &gw.ListenAddr, &gw.PublicIP,
		&resourcesJSON, &gw.AuthMode, &fedConfigJSON, &createdAt, &updatedAt, &lastSeenAt)
	if err != nil {
		return nil, false
	}
	gw.TenantIDs = fromJSON[[]string](tenantIDsJSON)
	if gw.TenantIDs == nil {
		gw.TenantIDs = []string{}
	}
	if gw.TenantID == "" && len(gw.TenantIDs) == 1 {
		gw.TenantID = gw.TenantIDs[0]
	}
	gw.AssignedResources = fromJSON[[]string](resourcesJSON)
	if fedConfigJSON != "" {
		gw.FederationConfig = fromJSONPtr[models.FederationConfig](fedConfigJSON)
	}
	if gw.AuthMode == "" {
		gw.AuthMode = "builtin"
	}
	gw.CreatedAt = parseTime(createdAt)
	gw.UpdatedAt = parseTime(updatedAt)
	gw.LastSeenAt = parseTime(lastSeenAt)
	return gw, true
}

// GetGatewayByOIDCClientID looks up a gateway by its OIDC client_id.
func (s *Store) GetGatewayByOIDCClientID(clientID string) (*models.Gateway, bool) {
	if clientID == "" {
		return nil, false
	}
	row := s.db.QueryRow(`SELECT id, name, fqdn, tenant_id, tenant_ids_json,
		enrollment_token, token_expires_at, status,
		cert_pem, cert_fingerprint, cert_serial, cert_expires_at,
		oidc_client_id, oidc_client_secret, listen_addr, public_ip,
		assigned_resources_json, auth_mode, federation_config_json,
		created_at, updated_at, last_seen_at
		FROM gateways WHERE oidc_client_id = ?`, clientID)
	return s.scanGateway(row)
}
