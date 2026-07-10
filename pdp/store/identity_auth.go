package store

import (
	"time"

	"pdp/models"
)

// GetUserByExternalSubject finds a federated user by their external IdP subject+source.
func (s *Store) GetUserByExternalSubject(externalSubject, authSource string) (*models.User, bool) {
	row := s.db.QueryRow(`SELECT `+userSelectColumns+`
		FROM users WHERE external_subject = ? AND auth_source = ?`, externalSubject, authSource)
	return s.scanUser(row)
}

func (s *Store) GetUserByExternalSubjectForOrganization(externalSubject, authSource, organizationID string) (*models.User, bool) {
	row := s.db.QueryRow(`SELECT `+userSelectColumns+`
		FROM users WHERE external_subject = ? AND auth_source = ? AND organization_id = ?`,
		externalSubject, authSource, organizationID)
	return s.scanUser(row)
}

// Login Locations (geo-velocity tracking)

// SaveLoginLocation stores a geolocation record for a user login event.
func (s *Store) SaveLoginLocation(userID, sourceIP string, lat, lon float64, city, country string) error {
	return s.SaveLoginLocationAt(userID, sourceIP, lat, lon, city, country, time.Now().UTC())
}

// SaveLoginLocationAt stores a geolocation record at a specific timestamp.
func (s *Store) SaveLoginLocationAt(userID, sourceIP string, lat, lon float64, city, country string, timestamp time.Time) error {
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}
	_, err := s.db.Exec(
		`INSERT INTO login_locations (user_id, source_ip, latitude, longitude, city, country, timestamp)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		userID, sourceIP, lat, lon, city, country, timestamp.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return err
	}

	s.db.Exec(
		`DELETE FROM login_locations WHERE user_id = ? AND id NOT IN (
			SELECT id FROM login_locations WHERE user_id = ? ORDER BY timestamp DESC LIMIT 50
		)`, userID, userID,
	)
	return nil
}

// GetLastLoginLocation returns the most recent login location for a user.
// Returns nil if no location exists.
func (s *Store) GetLastLoginLocation(userID string) (*models.LoginLocation, error) {
	row := s.db.QueryRow(
		`SELECT user_id, source_ip, latitude, longitude, city, country, timestamp
		 FROM login_locations WHERE user_id = ? ORDER BY timestamp DESC LIMIT 1`, userID,
	)

	loc := &models.LoginLocation{}
	var ts string
	err := row.Scan(&loc.UserID, &loc.SourceIP, &loc.Latitude, &loc.Longitude, &loc.City, &loc.Country, &ts)
	if err != nil {
		return nil, err
	}
	loc.Timestamp = parseTime(ts)
	return loc, nil
}

// GetRecentLoginLocations returns the N most recent login locations for a user.
func (s *Store) GetRecentLoginLocations(userID string, limit int) ([]*models.LoginLocation, error) {
	rows, err := s.db.Query(
		`SELECT user_id, source_ip, latitude, longitude, city, country, timestamp
		 FROM login_locations WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?`, userID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var locs []*models.LoginLocation
	for rows.Next() {
		loc := &models.LoginLocation{}
		var ts string
		if err := rows.Scan(&loc.UserID, &loc.SourceIP, &loc.Latitude, &loc.Longitude, &loc.City, &loc.Country, &ts); err != nil {
			continue
		}
		loc.Timestamp = parseTime(ts)
		locs = append(locs, loc)
	}
	return locs, nil
}

// WebAuthn Credentials

// SaveWebAuthnCredential persists a new WebAuthn credential for a user.
func (s *Store) SaveWebAuthnCredential(cred *models.WebAuthnCredential) error {
	_, err := s.db.Exec(
		`INSERT INTO webauthn_credentials (id, user_id, credential_id, credential_json, name, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		cred.ID, cred.UserID, cred.CredentialID, cred.CredentialJSON,
		cred.Name, fmtTime(cred.CreatedAt),
	)
	return err
}

// GetWebAuthnCredentials returns all WebAuthn credentials for a user.
func (s *Store) GetWebAuthnCredentials(userID string) ([]*models.WebAuthnCredential, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, credential_id, credential_json, name, created_at
		 FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []*models.WebAuthnCredential
	for rows.Next() {
		c := &models.WebAuthnCredential{}
		var createdAt string
		if err := rows.Scan(&c.ID, &c.UserID, &c.CredentialID, &c.CredentialJSON, &c.Name, &createdAt); err != nil {
			continue
		}
		c.CreatedAt = parseTime(createdAt)
		creds = append(creds, c)
	}
	return creds, nil
}

// UpdateWebAuthnCredentialJSON updates the JSON blob for a credential (e.g. after sign count bump).
func (s *Store) UpdateWebAuthnCredentialJSON(credID, credJSON string) error {
	_, err := s.db.Exec(
		`UPDATE webauthn_credentials SET credential_json = ? WHERE credential_id = ?`,
		credJSON, credID,
	)
	return err
}

// DeleteWebAuthnCredential removes a WebAuthn credential by row ID.
func (s *Store) DeleteWebAuthnCredential(id string) error {
	_, err := s.db.Exec(`DELETE FROM webauthn_credentials WHERE id = ?`, id)
	return err
}

// DeleteWebAuthnCredentialsForUser removes all WebAuthn credentials for a user.
func (s *Store) DeleteWebAuthnCredentialsForUser(userID string) error {
	_, err := s.db.Exec(`DELETE FROM webauthn_credentials WHERE user_id = ?`, userID)
	return err
}

// GetUserDevices returns device IDs bound to a user, most recently bound first.
func (s *Store) GetUserDevices(userID string) []string {
	rows, err := s.db.Query(
		`SELECT device_id FROM device_users WHERE user_id = ? ORDER BY bound_at DESC`, userID,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var devices []string
	for rows.Next() {
		var d string
		if rows.Scan(&d) == nil {
			devices = append(devices, d)
		}
	}
	return devices
}

// GetDeviceUserBinding returns the earliest known binding between a user and a device.
func (s *Store) GetDeviceUserBinding(userID, deviceID string) (*models.DeviceUser, bool) {
	row := s.db.QueryRow(
		`SELECT device_id, user_id, username, role, bound_at
		 FROM device_users
		 WHERE user_id = ? AND device_id = ?
		 ORDER BY bound_at ASC
		 LIMIT 1`, userID, deviceID,
	)

	binding := &models.DeviceUser{}
	var boundAt string
	if err := row.Scan(&binding.DeviceID, &binding.UserID, &binding.Username, &binding.Role, &boundAt); err != nil {
		return nil, false
	}
	binding.BoundAt = parseTime(boundAt)
	return binding, true
}
