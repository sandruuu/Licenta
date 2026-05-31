package store

import (
	"log"
	"time"

	"pdp/models"

	_ "modernc.org/sqlite"
)

// ─────────────────────────────────────────────
// Device Health operations
// ─────────────────────────────────────────────

func (s *Store) SaveDeviceHealth(report *models.DeviceHealthReport) {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO device_health
		(device_id, hostname, os, checks_json, overall_score, reported_at, tenant_id)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		report.DeviceID, report.Hostname, report.OS, toJSON(report.Checks),
		report.OverallScore, fmtTime(report.ReportedAt), report.TenantID)
	if err != nil {
		log.Printf("[STORE] Failed to save device health for %s: %v", report.DeviceID, err)
	}
}

// TouchDeviceHealth bumps the reported_at timestamp for an existing device
// health record without rewriting the (potentially large) checks_json
// payload. Kept for old scored health records; current TrustAgent uses the
// gRPC device data heartbeat path.
//
// Returns true if a row was updated, false if the device has no prior
// health report on file.
func (s *Store) TouchDeviceHealth(deviceID string, ts time.Time) bool {
	res, err := s.db.Exec(`UPDATE device_health SET reported_at = ? WHERE device_id = ?`,
		fmtTime(ts), deviceID)
	if err != nil {
		log.Printf("[STORE] Failed to touch device health for %s: %v", deviceID, err)
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

func (s *Store) TouchDeviceData(deviceID string, ts time.Time) bool {
	res, err := s.db.Exec(`UPDATE device_data SET reported_at = ? WHERE device_id = ?`, fmtTime(ts), deviceID)
	if err != nil {
		log.Printf("[STORE] Failed to touch device data for %s: %v", deviceID, err)
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

func (s *Store) GetDeviceHealth(deviceID string) (*models.DeviceHealthReport, bool) {
	row := s.db.QueryRow(`SELECT device_id, hostname, os, checks_json, overall_score, reported_at, tenant_id
		FROM device_health WHERE device_id = ?`, deviceID)

	r := &models.DeviceHealthReport{}
	var checksJSON, reportedAt string

	err := row.Scan(&r.DeviceID, &r.Hostname, &r.OS, &checksJSON, &r.OverallScore, &reportedAt, &r.TenantID)
	if err != nil {
		return nil, false
	}

	r.Checks = fromJSON[[]models.HealthCheck](checksJSON)
	r.ReportedAt = parseTime(reportedAt)
	return r, true
}

func (s *Store) ListDeviceHealth() []*models.DeviceHealthReport {
	rows, err := s.db.Query("SELECT device_id, hostname, os, checks_json, overall_score, reported_at, tenant_id FROM device_health")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var reports []*models.DeviceHealthReport
	for rows.Next() {
		r := &models.DeviceHealthReport{}
		var checksJSON, reportedAt string

		if err := rows.Scan(&r.DeviceID, &r.Hostname, &r.OS, &checksJSON, &r.OverallScore, &reportedAt, &r.TenantID); err != nil {
			continue
		}

		r.Checks = fromJSON[[]models.HealthCheck](checksJSON)
		r.ReportedAt = parseTime(reportedAt)
		reports = append(reports, r)
	}
	return reports
}

func (s *Store) SaveDeviceData(report *models.DeviceDataReport) {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO device_data
		(device_id, hostname, os, checks_json, collected_at, reported_at, tenant_id)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		report.DeviceID, report.Hostname, report.OS, toJSON(report.Checks),
		fmtTime(report.CollectedAt), fmtTime(report.ReportedAt), report.TenantID)
	if err != nil {
		log.Printf("[STORE] Failed to save device data for %s: %v", report.DeviceID, err)
	}
}

func (s *Store) GetDeviceData(deviceID string) (*models.DeviceDataReport, bool) {
	row := s.db.QueryRow(`SELECT device_id, hostname, os, checks_json, collected_at, reported_at, tenant_id
		FROM device_data WHERE device_id = ?`, deviceID)

	report := &models.DeviceDataReport{}
	var checksJSON, collectedAt, reportedAt string
	if err := row.Scan(&report.DeviceID, &report.Hostname, &report.OS, &checksJSON, &collectedAt, &reportedAt, &report.TenantID); err != nil {
		return nil, false
	}
	report.Checks = fromJSON[[]models.HealthCheck](checksJSON)
	report.CollectedAt = parseTime(collectedAt)
	report.ReportedAt = parseTime(reportedAt)
	return report, true
}

func (s *Store) ListDeviceData() []*models.DeviceDataReport {
	rows, err := s.db.Query("SELECT device_id, hostname, os, checks_json, collected_at, reported_at, tenant_id FROM device_data")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var reports []*models.DeviceDataReport
	for rows.Next() {
		report := &models.DeviceDataReport{}
		var checksJSON, collectedAt, reportedAt string
		if err := rows.Scan(&report.DeviceID, &report.Hostname, &report.OS, &checksJSON, &collectedAt, &reportedAt, &report.TenantID); err != nil {
			continue
		}
		report.Checks = fromJSON[[]models.HealthCheck](checksJSON)
		report.CollectedAt = parseTime(collectedAt)
		report.ReportedAt = parseTime(reportedAt)
		reports = append(reports, report)
	}
	return reports
}
