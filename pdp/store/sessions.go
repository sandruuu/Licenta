package store

import (
	"database/sql"
	"log"
	"time"

	"pdp/models"
)

// ─────────────────────────────────────────────
// Session operations
// ─────────────────────────────────────────────

func (s *Store) GetSession(id string) (*models.Session, bool) {
	row := s.db.QueryRow(`SELECT id, user_id, username, device_id, source_ip, resource,
		gateway_id, protocol, risk_score, organization_id, policy_id, created_at, expires_at, last_activity,
		revalidate_after, session_max_age_seconds, revalidate_every_seconds,
		revoke_on_posture_change, revoke_on_risk_increase, revoked
		FROM sessions WHERE id = ?`, id)

	sess := &models.Session{}
	var revoked, revokeOnPostureChange, revokeOnRiskIncrease int
	var createdAt, expiresAt, lastActivity, revalidateAfter string

	err := row.Scan(&sess.ID, &sess.UserID, &sess.Username, &sess.DeviceID, &sess.SourceIP,
		&sess.Resource, &sess.GatewayID, &sess.Protocol, &sess.RiskScore, &sess.OrganizationID, &sess.PolicyID,
		&createdAt, &expiresAt, &lastActivity, &revalidateAfter, &sess.SessionMaxAgeSeconds,
		&sess.RevalidateEverySeconds, &revokeOnPostureChange, &revokeOnRiskIncrease, &revoked)
	if err != nil {
		return nil, false
	}

	sess.Revoked = i2b(revoked)
	sess.RevokeOnPostureChange = i2b(revokeOnPostureChange)
	sess.RevokeOnRiskIncrease = i2b(revokeOnRiskIncrease)
	sess.CreatedAt = parseTime(createdAt)
	sess.ExpiresAt = parseTime(expiresAt)
	sess.LastActivity = parseTime(lastActivity)
	sess.RevalidateAfter = parseTime(revalidateAfter)
	return sess, true
}

func (s *Store) SaveSession(session *models.Session) {
	_, err := s.db.Exec(`INSERT INTO sessions
		(id, user_id, username, device_id, source_ip, resource, gateway_id, protocol, risk_score,
		 organization_id, policy_id, created_at, expires_at, last_activity, revalidate_after,
		 session_max_age_seconds, revalidate_every_seconds, revoke_on_posture_change,
		 revoke_on_risk_increase, revoked)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			user_id = EXCLUDED.user_id,
			username = EXCLUDED.username,
			device_id = EXCLUDED.device_id,
			source_ip = EXCLUDED.source_ip,
			resource = EXCLUDED.resource,
			gateway_id = EXCLUDED.gateway_id,
			protocol = EXCLUDED.protocol,
			risk_score = EXCLUDED.risk_score,
			organization_id = EXCLUDED.organization_id,
			policy_id = EXCLUDED.policy_id,
			created_at = EXCLUDED.created_at,
			expires_at = EXCLUDED.expires_at,
			last_activity = EXCLUDED.last_activity,
			revalidate_after = EXCLUDED.revalidate_after,
			session_max_age_seconds = EXCLUDED.session_max_age_seconds,
			revalidate_every_seconds = EXCLUDED.revalidate_every_seconds,
			revoke_on_posture_change = EXCLUDED.revoke_on_posture_change,
			revoke_on_risk_increase = EXCLUDED.revoke_on_risk_increase,
			revoked = EXCLUDED.revoked`,
		session.ID, session.UserID, session.Username, session.DeviceID, session.SourceIP,
		session.Resource, session.GatewayID, session.Protocol, session.RiskScore, session.OrganizationID, session.PolicyID,
		fmtTime(session.CreatedAt), fmtTime(session.ExpiresAt),
		fmtTime(session.LastActivity), fmtTime(session.RevalidateAfter),
		session.SessionMaxAgeSeconds, session.RevalidateEverySeconds,
		b2i(session.RevokeOnPostureChange), b2i(session.RevokeOnRiskIncrease), b2i(session.Revoked))
	if err != nil {
		log.Printf("[STORE] Failed to save session %s: %v", session.ID, err)
	}
}

func (s *Store) ListSessions() []*models.Session {
	rows, err := s.db.Query(`SELECT id, user_id, username, device_id, source_ip, resource,
		gateway_id, protocol, risk_score, organization_id, policy_id, created_at, expires_at, last_activity,
		revalidate_after, session_max_age_seconds, revalidate_every_seconds,
		revoke_on_posture_change, revoke_on_risk_increase, revoked
		FROM sessions WHERE revoked = 0 AND expires_at > ?`, fmtTime(time.Now()))
	if err != nil {
		return nil
	}
	defer rows.Close()
	return s.scanSessions(rows)
}

func (s *Store) ListUserSessions(userID string) []*models.Session {
	rows, err := s.db.Query(`SELECT id, user_id, username, device_id, source_ip, resource,
		gateway_id, protocol, risk_score, organization_id, policy_id, created_at, expires_at, last_activity,
		revalidate_after, session_max_age_seconds, revalidate_every_seconds,
		revoke_on_posture_change, revoke_on_risk_increase, revoked
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
		var revoked, revokeOnPostureChange, revokeOnRiskIncrease int
		var createdAt, expiresAt, lastActivity, revalidateAfter string

		if err := rows.Scan(&sess.ID, &sess.UserID, &sess.Username, &sess.DeviceID, &sess.SourceIP,
			&sess.Resource, &sess.GatewayID, &sess.Protocol, &sess.RiskScore, &sess.OrganizationID, &sess.PolicyID,
			&createdAt, &expiresAt, &lastActivity, &revalidateAfter, &sess.SessionMaxAgeSeconds,
			&sess.RevalidateEverySeconds, &revokeOnPostureChange, &revokeOnRiskIncrease, &revoked); err != nil {
			continue
		}

		sess.Revoked = i2b(revoked)
		sess.RevokeOnPostureChange = i2b(revokeOnPostureChange)
		sess.RevokeOnRiskIncrease = i2b(revokeOnRiskIncrease)
		sess.CreatedAt = parseTime(createdAt)
		sess.ExpiresAt = parseTime(expiresAt)
		sess.LastActivity = parseTime(lastActivity)
		sess.RevalidateAfter = parseTime(revalidateAfter)
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
		gateway_id, protocol, risk_score, organization_id, policy_id, created_at, expires_at, last_activity,
		revalidate_after, session_max_age_seconds, revalidate_every_seconds,
		revoke_on_posture_change, revoke_on_risk_increase, revoked
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
