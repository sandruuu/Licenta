package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"log"
	"strings"
	"time"

	"pdp/models"
)

// Gateway operations

func (s *Store) SaveGateway(gw *models.Gateway) error {
	resources := gw.AssignedResources
	if resources == nil {
		resources = []string{}
	}
	organizationIDs := gw.OrganizationIDs
	if organizationIDs == nil {
		organizationIDs = []string{}
	}
	if gw.OrganizationID != "" && len(organizationIDs) == 0 {
		organizationIDs = []string{gw.OrganizationID}
	}

	_, err := s.db.Exec(`INSERT INTO gateways
		(id, name, fqdn, organization_id, organization_ids_json, enrollment_token, token_expires_at, status,
		 cert_pem, cert_fingerprint, cert_serial, cert_expires_at,
		 listen_addr, public_ip, assigned_resources_json,
		 created_at, updated_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			fqdn = EXCLUDED.fqdn,
			organization_id = EXCLUDED.organization_id,
			organization_ids_json = EXCLUDED.organization_ids_json,
			enrollment_token = EXCLUDED.enrollment_token,
			token_expires_at = EXCLUDED.token_expires_at,
			status = EXCLUDED.status,
			cert_pem = EXCLUDED.cert_pem,
			cert_fingerprint = EXCLUDED.cert_fingerprint,
			cert_serial = EXCLUDED.cert_serial,
			cert_expires_at = EXCLUDED.cert_expires_at,
			listen_addr = EXCLUDED.listen_addr,
			public_ip = EXCLUDED.public_ip,
			assigned_resources_json = EXCLUDED.assigned_resources_json,
			created_at = EXCLUDED.created_at,
			updated_at = EXCLUDED.updated_at,
			last_seen_at = EXCLUDED.last_seen_at`,
		gw.ID, gw.Name, gw.FQDN, gw.OrganizationID, toJSON(organizationIDs),
		gw.EnrollmentToken, gw.TokenExpiresAt, gw.Status,
		gw.CertPEM, gw.CertFingerprint, gw.CertSerial, gw.CertExpiresAt,
		gw.ListenAddr, gw.PublicIP, toJSON(resources),
		fmtTime(gw.CreatedAt), fmtTime(gw.UpdatedAt), fmtTime(gw.LastSeenAt))
	if err != nil {
		log.Printf("[STORE] Failed to save gateway %s: %v", gw.ID, err)
		return err
	}
	return nil
}

func (s *Store) GetGateway(id string) (*models.Gateway, bool) {
	row := s.db.QueryRow(`SELECT id, name, fqdn, organization_id, organization_ids_json,
		enrollment_token, token_expires_at, status,
		cert_pem, cert_fingerprint, cert_serial, cert_expires_at,
		listen_addr, public_ip, assigned_resources_json,
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
	row := s.db.QueryRow(`SELECT id, name, fqdn, organization_id, organization_ids_json,
		enrollment_token, token_expires_at, status,
		cert_pem, cert_fingerprint, cert_serial, cert_expires_at,
		listen_addr, public_ip, assigned_resources_json,
		created_at, updated_at, last_seen_at
		FROM gateways WHERE enrollment_token = ?`, tokenHash)
	return s.scanGateway(row)
}

// ConsumeGatewayEnrollmentToken consumes a pending gateway enrollment token.
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
	row := s.db.QueryRow(`SELECT id, name, fqdn, organization_id, organization_ids_json,
		enrollment_token, token_expires_at, status,
		cert_pem, cert_fingerprint, cert_serial, cert_expires_at,
		listen_addr, public_ip, assigned_resources_json,
		created_at, updated_at, last_seen_at
		FROM gateways WHERE fqdn = ?`, fqdn)
	return s.scanGateway(row)
}

func (s *Store) ListGateways() []*models.Gateway {
	rows, err := s.db.Query(`SELECT id, name, fqdn, organization_id, organization_ids_json,
		enrollment_token, token_expires_at, status,
		cert_pem, cert_fingerprint, cert_serial, cert_expires_at,
		listen_addr, public_ip, assigned_resources_json,
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
		var organizationIDsJSON, resourcesJSON, createdAt, updatedAt, lastSeenAt string
		if err := rows.Scan(&gw.ID, &gw.Name, &gw.FQDN, &gw.OrganizationID, &organizationIDsJSON,
			&gw.EnrollmentToken, &gw.TokenExpiresAt, &gw.Status,
			&gw.CertPEM, &gw.CertFingerprint, &gw.CertSerial, &gw.CertExpiresAt,
			&gw.ListenAddr, &gw.PublicIP, &resourcesJSON, &createdAt, &updatedAt, &lastSeenAt); err != nil {
			continue
		}
		gw.OrganizationIDs = fromJSON[[]string](organizationIDsJSON)
		if gw.OrganizationIDs == nil {
			gw.OrganizationIDs = []string{}
		}
		if gw.OrganizationID == "" && len(gw.OrganizationIDs) == 1 {
			gw.OrganizationID = gw.OrganizationIDs[0]
		}
		gw.AssignedResources = fromJSON[[]string](resourcesJSON)
		gw.CreatedAt = parseTime(createdAt)
		gw.UpdatedAt = parseTime(updatedAt)
		gw.LastSeenAt = parseTime(lastSeenAt)
		gateways = append(gateways, gw)
	}
	return gateways
}

func (s *Store) ListGatewaysByOrganization(organizationID string) []*models.Gateway {
	gateways := s.ListGateways()
	filtered := make([]*models.Gateway, 0, len(gateways))
	for _, gateway := range gateways {
		if gateway == nil {
			continue
		}
		if strings.TrimSpace(gateway.OrganizationID) == strings.TrimSpace(organizationID) {
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
	var organizationIDsJSON, resourcesJSON, createdAt, updatedAt, lastSeenAt string
	err := row.Scan(&gw.ID, &gw.Name, &gw.FQDN, &gw.OrganizationID, &organizationIDsJSON,
		&gw.EnrollmentToken, &gw.TokenExpiresAt, &gw.Status,
		&gw.CertPEM, &gw.CertFingerprint, &gw.CertSerial, &gw.CertExpiresAt,
		&gw.ListenAddr, &gw.PublicIP, &resourcesJSON, &createdAt, &updatedAt, &lastSeenAt)
	if err != nil {
		return nil, false
	}
	gw.OrganizationIDs = fromJSON[[]string](organizationIDsJSON)
	if gw.OrganizationIDs == nil {
		gw.OrganizationIDs = []string{}
	}
	if gw.OrganizationID == "" && len(gw.OrganizationIDs) == 1 {
		gw.OrganizationID = gw.OrganizationIDs[0]
	}
	gw.AssignedResources = fromJSON[[]string](resourcesJSON)
	gw.CreatedAt = parseTime(createdAt)
	gw.UpdatedAt = parseTime(updatedAt)
	gw.LastSeenAt = parseTime(lastSeenAt)
	return gw, true
}
