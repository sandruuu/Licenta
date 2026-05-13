package store

import (
	"database/sql"
	"log"
	"time"

	"pdp/models"

	_ "modernc.org/sqlite"
)

// ─────────────────────────────────────────────
// Session operations
// ─────────────────────────────────────────────

func (s *Store) GetSession(id string) (*models.Session, bool) {
	row := s.db.QueryRow(`SELECT id, user_id, username, device_id, source_ip, resource,
		gateway_id, protocol, risk_score, tenant_id, created_at, expires_at, last_activity, revoked
		FROM sessions WHERE id = ?`, id)

	sess := &models.Session{}
	var revoked int
	var createdAt, expiresAt, lastActivity string

	err := row.Scan(&sess.ID, &sess.UserID, &sess.Username, &sess.DeviceID, &sess.SourceIP,
		&sess.Resource, &sess.GatewayID, &sess.Protocol, &sess.RiskScore, &sess.TenantID, &createdAt, &expiresAt, &lastActivity, &revoked)
	if err != nil {
		return nil, false
	}

	sess.Revoked = i2b(revoked)
	sess.CreatedAt = parseTime(createdAt)
	sess.ExpiresAt = parseTime(expiresAt)
	sess.LastActivity = parseTime(lastActivity)
	return sess, true
}

func (s *Store) SaveSession(session *models.Session) {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO sessions
		(id, user_id, username, device_id, source_ip, resource, gateway_id, protocol, risk_score,
		 tenant_id, created_at, expires_at, last_activity, revoked)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		session.ID, session.UserID, session.Username, session.DeviceID, session.SourceIP,
		session.Resource, session.GatewayID, session.Protocol, session.RiskScore, session.TenantID,
		fmtTime(session.CreatedAt), fmtTime(session.ExpiresAt),
		fmtTime(session.LastActivity), b2i(session.Revoked))
	if err != nil {
		log.Printf("[STORE] Failed to save session %s: %v", session.ID, err)
	}
}

func (s *Store) ListSessions() []*models.Session {
	rows, err := s.db.Query(`SELECT id, user_id, username, device_id, source_ip, resource,
		gateway_id, protocol, risk_score, tenant_id, created_at, expires_at, last_activity, revoked
		FROM sessions WHERE revoked = 0 AND expires_at > ?`, fmtTime(time.Now()))
	if err != nil {
		return nil
	}
	defer rows.Close()
	return s.scanSessions(rows)
}

func (s *Store) ListUserSessions(userID string) []*models.Session {
	rows, err := s.db.Query(`SELECT id, user_id, username, device_id, source_ip, resource,
		gateway_id, protocol, risk_score, tenant_id, created_at, expires_at, last_activity, revoked
		FROM sessions WHERE user_id = ? AND revoked = 0 AND expires_at > ?`, userID, fmtTime(time.Now()))
	if err != nil {
		return nil
	}
	defer rows.Close()
	return s.scanSessions(rows)
}

func (s *Store) scanSessions(rows *sql.Rows) []*models.Session {
	var sessions []*models.Session
	for rows.Next() {
		sess := &models.Session{}
		var revoked int
		var createdAt, expiresAt, lastActivity string

		if err := rows.Scan(&sess.ID, &sess.UserID, &sess.Username, &sess.DeviceID, &sess.SourceIP,
			&sess.Resource, &sess.GatewayID, &sess.Protocol, &sess.RiskScore, &sess.TenantID, &createdAt, &expiresAt, &lastActivity, &revoked); err != nil {
			continue
		}

		sess.Revoked = i2b(revoked)
		sess.CreatedAt = parseTime(createdAt)
		sess.ExpiresAt = parseTime(expiresAt)
		sess.LastActivity = parseTime(lastActivity)
		sessions = append(sessions, sess)
	}
	return sessions
}

func (s *Store) RevokeSession(id string) bool {
	result, err := s.db.Exec("UPDATE sessions SET revoked = 1 WHERE id = ?", id)
	if err != nil {
		return false
	}
	n, _ := result.RowsAffected()
	return n > 0
}

func (s *Store) CleanExpiredSessions() int {
	_, count := s.CleanExpiredSessionsWithSnapshot(time.Now())
	return count
}

func (s *Store) CleanExpiredSessionsWithSnapshot(now time.Time) ([]*models.Session, int) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, 0
	}
	defer tx.Rollback()

	rows, err := tx.Query(`SELECT id, user_id, username, device_id, source_ip, resource,
		gateway_id, protocol, risk_score, tenant_id, created_at, expires_at, last_activity, revoked
		FROM sessions WHERE revoked = 0 AND expires_at < ?`, fmtTime(now))
	if err != nil {
		return nil, 0
	}
	expired := s.scanSessions(rows)
	rows.Close()

	result, err := tx.Exec("DELETE FROM sessions WHERE expires_at < ? OR revoked = 1", fmtTime(now))
	if err != nil {
		return nil, 0
	}
	n, _ := result.RowsAffected()
	if err := tx.Commit(); err != nil {
		return nil, 0
	}
	return expired, int(n)
}
