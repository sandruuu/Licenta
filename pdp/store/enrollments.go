package store

import (
	"database/sql"
	"log"
	"time"

	"pdp/models"

	_ "modernc.org/sqlite"
)

// ─────────────────────────────────────────────
// Device Enrollment
// ─────────────────────────────────────────────

// SaveDeviceEnrollment creates or updates a device enrollment record
func (s *Store) SaveDeviceEnrollment(e *models.DeviceEnrollment) {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO device_enrollments
		(id, device_id, component, hostname, public_key_fingerprint, cert_fingerprint, cert_serial, status, csr_pem, cert_pem, enrolled_at, expires_at, approved_by, user_id, username, tenant_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.DeviceID, e.Component, e.Hostname, e.PublicKeyFingerprint, e.CertFingerprint, e.CertSerial,
		e.Status, e.CSRPEM, e.CertPEM, fmtTime(e.EnrolledAt), fmtTime(e.ExpiresAt), e.ApprovedBy, e.UserID, e.Username, e.TenantID)
	if err != nil {
		log.Printf("[STORE] Failed to save device enrollment %s: %v", e.ID, err)
	}
}

// GetDeviceEnrollment retrieves an enrollment by ID
func (s *Store) GetDeviceEnrollment(id string) (*models.DeviceEnrollment, bool) {
	row := s.db.QueryRow(`SELECT id, device_id, component, hostname, public_key_fingerprint, cert_fingerprint, cert_serial,
		status, csr_pem, cert_pem, enrolled_at, expires_at, approved_by, user_id, username, tenant_id
		FROM device_enrollments WHERE id = ?`, id)
	return s.scanEnrollment(row)
}

// GetDeviceEnrollmentByDeviceID retrieves an enrollment by device_id
func (s *Store) GetDeviceEnrollmentByDeviceID(deviceID string) (*models.DeviceEnrollment, bool) {
	row := s.db.QueryRow(`SELECT id, device_id, component, hostname, public_key_fingerprint, cert_fingerprint, cert_serial,
		status, csr_pem, cert_pem, enrolled_at, expires_at, approved_by, user_id, username, tenant_id
		FROM device_enrollments WHERE device_id = ? ORDER BY enrolled_at DESC LIMIT 1`, deviceID)
	return s.scanEnrollment(row)
}

// GetDeviceEnrollmentByComponent retrieves an enrollment by device_id and component
func (s *Store) GetDeviceEnrollmentByComponent(deviceID, component string) (*models.DeviceEnrollment, bool) {
	row := s.db.QueryRow(`SELECT id, device_id, component, hostname, public_key_fingerprint, cert_fingerprint, cert_serial,
		status, csr_pem, cert_pem, enrolled_at, expires_at, approved_by, user_id, username, tenant_id
		FROM device_enrollments WHERE device_id = ? AND component = ? ORDER BY enrolled_at DESC LIMIT 1`, deviceID, component)
	return s.scanEnrollment(row)
}

// ListDeviceEnrollments returns all enrollments
func (s *Store) ListDeviceEnrollments() []*models.DeviceEnrollment {
	rows, err := s.db.Query(`SELECT id, device_id, component, hostname, public_key_fingerprint, cert_fingerprint, cert_serial,
		status, csr_pem, cert_pem, enrolled_at, expires_at, approved_by, user_id, username, tenant_id
		FROM device_enrollments ORDER BY enrolled_at DESC`)
	if err != nil {
		log.Printf("[STORE] Failed to list enrollments: %v", err)
		return nil
	}
	defer rows.Close()

	var enrollments []*models.DeviceEnrollment
	for rows.Next() {
		e := &models.DeviceEnrollment{}
		var enrolledAt, expiresAt string
		if err := rows.Scan(&e.ID, &e.DeviceID, &e.Component, &e.Hostname, &e.PublicKeyFingerprint, &e.CertFingerprint, &e.CertSerial,
			&e.Status, &e.CSRPEM, &e.CertPEM, &enrolledAt, &expiresAt, &e.ApprovedBy, &e.UserID, &e.Username, &e.TenantID); err != nil {
			continue
		}
		e.EnrolledAt = parseTime(enrolledAt)
		e.ExpiresAt = parseTime(expiresAt)
		enrollments = append(enrollments, e)
	}
	return enrollments
}

func (s *Store) scanEnrollment(row *sql.Row) (*models.DeviceEnrollment, bool) {
	e := &models.DeviceEnrollment{}
	var enrolledAt, expiresAt string
	err := row.Scan(&e.ID, &e.DeviceID, &e.Component, &e.Hostname, &e.PublicKeyFingerprint, &e.CertFingerprint, &e.CertSerial,
		&e.Status, &e.CSRPEM, &e.CertPEM, &enrolledAt, &expiresAt, &e.ApprovedBy, &e.UserID, &e.Username, &e.TenantID)
	if err != nil {
		return nil, false
	}
	e.EnrolledAt = parseTime(enrolledAt)
	e.ExpiresAt = parseTime(expiresAt)
	return e, true
}

// ─────────────────────────────────────────────
// Revoked certificate serial tracking
// ─────────────────────────────────────────────

// RevokeCertSerial records a revoked certificate serial for gateway cache sync
func (s *Store) RevokeCertSerial(serial, deviceID string, expiresOn time.Time) {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO revoked_certs (cert_serial, device_id, revoked_at, expires_on)
		VALUES (?, ?, ?, ?)`, serial, deviceID, fmtTime(time.Now()), fmtTime(expiresOn))
	if err != nil {
		log.Printf("[STORE] Failed to revoke cert serial %s: %v", serial, err)
	}
}

// GetRevokedSerials returns all revoked cert serials that haven't expired yet
func (s *Store) GetRevokedSerials() []string {
	rows, err := s.db.Query(`SELECT cert_serial FROM revoked_certs WHERE expires_on > ?`, fmtTime(time.Now()))
	if err != nil {
		log.Printf("[STORE] Failed to get revoked serials: %v", err)
		return nil
	}
	defer rows.Close()

	var serials []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err == nil {
			serials = append(serials, s)
		}
	}
	return serials
}

// ─────────────────────────────────────────────
// Device-User Binding
// ─────────────────────────────────────────────

// SaveDeviceUser creates or updates a device-user binding
func (s *Store) SaveDeviceUser(du *models.DeviceUser) {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO device_users (device_id, user_id, username, role, bound_at)
		VALUES (?, ?, ?, ?, ?)`,
		du.DeviceID, du.UserID, du.Username, du.Role, fmtTime(du.BoundAt))
	if err != nil {
		log.Printf("[STORE] Failed to save device-user binding %s/%s: %v", du.DeviceID, du.UserID, err)
	}
}
