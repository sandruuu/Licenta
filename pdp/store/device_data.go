package store

import (
	"log"

	"pdp/models"
)

func (s *Store) SaveDeviceData(report *models.DeviceDataReport) {
	_, err := s.db.Exec(`INSERT INTO device_data
		(device_id, user_id, username, agent_session_id, hostname, os, checks_json, collected_at, reported_at, organization_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (device_id) DO UPDATE SET
			user_id = EXCLUDED.user_id,
			username = EXCLUDED.username,
			agent_session_id = EXCLUDED.agent_session_id,
			hostname = EXCLUDED.hostname,
			os = EXCLUDED.os,
			checks_json = EXCLUDED.checks_json,
			collected_at = EXCLUDED.collected_at,
			reported_at = EXCLUDED.reported_at,
			organization_id = EXCLUDED.organization_id`,
		report.DeviceID, report.UserID, report.Username, report.AgentSessionID, report.Hostname, report.OS, toJSON(report.Checks),
		fmtTime(report.CollectedAt), fmtTime(report.ReportedAt), report.OrganizationID)
	if err != nil {
		log.Printf("[STORE] Failed to save device data for %s: %v", report.DeviceID, err)
	}
}

func (s *Store) GetDeviceData(deviceID string) (*models.DeviceDataReport, bool) {
	row := s.db.QueryRow(`SELECT device_id, user_id, username, agent_session_id, hostname, os, checks_json, collected_at, reported_at, organization_id
		FROM device_data WHERE device_id = ?`, deviceID)

	report := &models.DeviceDataReport{}
	var checksJSON, collectedAt, reportedAt string
	if err := row.Scan(&report.DeviceID, &report.UserID, &report.Username, &report.AgentSessionID, &report.Hostname, &report.OS, &checksJSON, &collectedAt, &reportedAt, &report.OrganizationID); err != nil {
		return nil, false
	}
	report.Checks = fromJSON[[]models.HealthCheck](checksJSON)
	report.CollectedAt = parseTime(collectedAt)
	report.ReportedAt = parseTime(reportedAt)
	return report, true
}

func (s *Store) ListDeviceData() []*models.DeviceDataReport {
	rows, err := s.db.Query("SELECT device_id, user_id, username, agent_session_id, hostname, os, checks_json, collected_at, reported_at, organization_id FROM device_data")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var reports []*models.DeviceDataReport
	for rows.Next() {
		report := &models.DeviceDataReport{}
		var checksJSON, collectedAt, reportedAt string
		if err := rows.Scan(&report.DeviceID, &report.UserID, &report.Username, &report.AgentSessionID, &report.Hostname, &report.OS, &checksJSON, &collectedAt, &reportedAt, &report.OrganizationID); err != nil {
			continue
		}
		report.Checks = fromJSON[[]models.HealthCheck](checksJSON)
		report.CollectedAt = parseTime(collectedAt)
		report.ReportedAt = parseTime(reportedAt)
		reports = append(reports, report)
	}
	return reports
}
