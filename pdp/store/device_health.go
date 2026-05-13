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
		(device_id, hostname, os, checks_json, overall_score, reported_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		report.DeviceID, report.Hostname, report.OS, toJSON(report.Checks),
		report.OverallScore, fmtTime(report.ReportedAt))
	if err != nil {
		log.Printf("[STORE] Failed to save device health for %s: %v", report.DeviceID, err)
	}
}

// TouchDeviceHealth bumps the reported_at timestamp for an existing device
// health record without rewriting the (potentially large) checks_json
// payload. Kept for legacy health records; current agent telemetry uses
// the gRPC device posture heartbeat path.
//
// Returns true if a row was updated, false if the device has no prior
// health report on file (in which case the caller should treat this as
// "no posture" rather than "fresh-but-unknown" posture).
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

func (s *Store) TouchDevicePosture(deviceID string, ts time.Time) bool {
	res, err := s.db.Exec(`UPDATE device_posture SET reported_at = ? WHERE device_id = ?`, fmtTime(ts), deviceID)
	if err != nil {
		log.Printf("[STORE] Failed to touch device posture for %s: %v", deviceID, err)
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

func (s *Store) GetDeviceHealth(deviceID string) (*models.DeviceHealthReport, bool) {
	row := s.db.QueryRow(`SELECT device_id, hostname, os, checks_json, overall_score, reported_at
		FROM device_health WHERE device_id = ?`, deviceID)

	r := &models.DeviceHealthReport{}
	var checksJSON, reportedAt string

	err := row.Scan(&r.DeviceID, &r.Hostname, &r.OS, &checksJSON, &r.OverallScore, &reportedAt)
	if err != nil {
		return nil, false
	}

	r.Checks = fromJSON[[]models.HealthCheck](checksJSON)
	r.ReportedAt = parseTime(reportedAt)
	return r, true
}

func (s *Store) ListDeviceHealth() []*models.DeviceHealthReport {
	rows, err := s.db.Query("SELECT device_id, hostname, os, checks_json, overall_score, reported_at FROM device_health")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var reports []*models.DeviceHealthReport
	for rows.Next() {
		r := &models.DeviceHealthReport{}
		var checksJSON, reportedAt string

		if err := rows.Scan(&r.DeviceID, &r.Hostname, &r.OS, &checksJSON, &r.OverallScore, &reportedAt); err != nil {
			continue
		}

		r.Checks = fromJSON[[]models.HealthCheck](checksJSON)
		r.ReportedAt = parseTime(reportedAt)
		reports = append(reports, r)
	}
	return reports
}

func (s *Store) SaveDevicePosture(report *models.DevicePostureReport) {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO device_posture
		(device_id, hostname, os, checks_json, collected_at, reported_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		report.DeviceID, report.Hostname, report.OS, toJSON(report.Checks),
		fmtTime(report.CollectedAt), fmtTime(report.ReportedAt))
	if err != nil {
		log.Printf("[STORE] Failed to save device posture for %s: %v", report.DeviceID, err)
	}
}

func (s *Store) GetDevicePosture(deviceID string) (*models.DevicePostureReport, bool) {
	row := s.db.QueryRow(`SELECT device_id, hostname, os, checks_json, collected_at, reported_at
		FROM device_posture WHERE device_id = ?`, deviceID)

	report := &models.DevicePostureReport{}
	var checksJSON, collectedAt, reportedAt string
	if err := row.Scan(&report.DeviceID, &report.Hostname, &report.OS, &checksJSON, &collectedAt, &reportedAt); err != nil {
		return nil, false
	}
	report.Checks = fromJSON[[]models.HealthCheck](checksJSON)
	report.CollectedAt = parseTime(collectedAt)
	report.ReportedAt = parseTime(reportedAt)
	return report, true
}

func (s *Store) ListDevicePosture() []*models.DevicePostureReport {
	rows, err := s.db.Query("SELECT device_id, hostname, os, checks_json, collected_at, reported_at FROM device_posture")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var reports []*models.DevicePostureReport
	for rows.Next() {
		report := &models.DevicePostureReport{}
		var checksJSON, collectedAt, reportedAt string
		if err := rows.Scan(&report.DeviceID, &report.Hostname, &report.OS, &checksJSON, &collectedAt, &reportedAt); err != nil {
			continue
		}
		report.Checks = fromJSON[[]models.HealthCheck](checksJSON)
		report.CollectedAt = parseTime(collectedAt)
		report.ReportedAt = parseTime(reportedAt)
		reports = append(reports, report)
	}
	return reports
}
