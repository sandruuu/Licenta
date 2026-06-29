package store

import (
	"database/sql"
	"strings"
	"time"

	"pdp/models"
)

type sessionScanner interface {
	Scan(dest ...any) error
}

// ─────────────────────────────────────────────
// Session operations
// ─────────────────────────────────────────────

func (s *Store) GetSession(id string) (*models.Session, bool) {
	row := s.db.QueryRow(`SELECT id, user_id, username, device_id, source_ip, resource,
		gateway_id, protocol, risk_signals_json, organization_id, policy_id, created_at, expires_at, last_activity,
		revalidate_after, step_up_acr, step_up_method, step_up_strength, step_up_aaguid, step_up_attachment, step_up_verified_at, step_up_expires_at,
		session_max_age_seconds, revalidate_every_seconds,
		revoke_on_posture_change, revoked
		FROM sessions WHERE id = ?`, id)

	sess, err := scanSession(row)
	if err != nil {
		return nil, false
	}
	return sess, true
}

func (s *Store) SaveSession(session *models.Session) error {
	_, err := s.db.Exec(`INSERT INTO sessions
		(id, user_id, username, device_id, source_ip, resource, gateway_id, protocol, risk_signals_json,
		 organization_id, policy_id, created_at, expires_at, last_activity, revalidate_after,
		 step_up_acr, step_up_method, step_up_strength, step_up_aaguid, step_up_attachment, step_up_verified_at, step_up_expires_at,
		 session_max_age_seconds, revalidate_every_seconds, revoke_on_posture_change,
		 revoked)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET
			user_id = EXCLUDED.user_id,
			username = EXCLUDED.username,
			device_id = EXCLUDED.device_id,
			source_ip = EXCLUDED.source_ip,
			resource = EXCLUDED.resource,
			gateway_id = EXCLUDED.gateway_id,
			protocol = EXCLUDED.protocol,
			risk_signals_json = EXCLUDED.risk_signals_json,
			organization_id = EXCLUDED.organization_id,
			policy_id = EXCLUDED.policy_id,
			created_at = EXCLUDED.created_at,
			expires_at = EXCLUDED.expires_at,
			last_activity = EXCLUDED.last_activity,
			revalidate_after = EXCLUDED.revalidate_after,
			step_up_acr = EXCLUDED.step_up_acr,
			step_up_method = EXCLUDED.step_up_method,
			step_up_strength = EXCLUDED.step_up_strength,
			step_up_aaguid = EXCLUDED.step_up_aaguid,
			step_up_attachment = EXCLUDED.step_up_attachment,
			step_up_verified_at = EXCLUDED.step_up_verified_at,
			step_up_expires_at = EXCLUDED.step_up_expires_at,
			session_max_age_seconds = EXCLUDED.session_max_age_seconds,
			revalidate_every_seconds = EXCLUDED.revalidate_every_seconds,
			revoke_on_posture_change = EXCLUDED.revoke_on_posture_change,
			revoked = EXCLUDED.revoked`,
		session.ID, session.UserID, session.Username, session.DeviceID, session.SourceIP,
		session.Resource, session.GatewayID, session.Protocol, toJSON(session.RiskSignals), session.OrganizationID, session.PolicyID,
		fmtTime(session.CreatedAt), fmtTime(session.ExpiresAt),
		fmtTime(session.LastActivity), fmtTime(session.RevalidateAfter),
		session.StepUpACR, session.StepUpMethod, session.StepUpStrength, session.StepUpAAGUID, session.StepUpAttachment,
		fmtTime(session.StepUpVerifiedAt), fmtTime(session.StepUpExpiresAt),
		session.SessionMaxAgeSeconds, session.RevalidateEverySeconds,
		b2i(session.RevokeOnPostureChange), b2i(session.Revoked))
	return err
}

func (s *Store) ListSessions() []*models.Session {
	rows, err := s.db.Query(`SELECT id, user_id, username, device_id, source_ip, resource,
		gateway_id, protocol, risk_signals_json, organization_id, policy_id, created_at, expires_at, last_activity,
		revalidate_after, step_up_acr, step_up_method, step_up_strength, step_up_aaguid, step_up_attachment, step_up_verified_at, step_up_expires_at,
		session_max_age_seconds, revalidate_every_seconds,
		revoke_on_posture_change, revoked
		FROM sessions WHERE revoked = 0 AND expires_at > ?`, fmtTime(time.Now()))
	if err != nil {
		return nil
	}
	defer rows.Close()
	return s.scanSessions(rows)
}

func (s *Store) ListUserSessions(userID string) []*models.Session {
	rows, err := s.db.Query(`SELECT id, user_id, username, device_id, source_ip, resource,
		gateway_id, protocol, risk_signals_json, organization_id, policy_id, created_at, expires_at, last_activity,
		revalidate_after, step_up_acr, step_up_method, step_up_strength, step_up_aaguid, step_up_attachment, step_up_verified_at, step_up_expires_at,
		session_max_age_seconds, revalidate_every_seconds,
		revoke_on_posture_change, revoked
		FROM sessions WHERE user_id = ? AND revoked = 0 AND expires_at > ?`, userID, fmtTime(time.Now()))
	if err != nil {
		return nil
	}
	defer rows.Close()
	return s.scanSessions(rows)
}

func (s *Store) FindReusableResourceSession(req models.AccessRequest, now time.Time) (*models.Session, bool) {
	if s == nil || s.db == nil {
		return nil, false
	}
	if now.IsZero() {
		now = time.Now()
	}
	row := s.db.QueryRow(`SELECT id, user_id, username, device_id, source_ip, resource,
		gateway_id, protocol, risk_signals_json, organization_id, policy_id, created_at, expires_at, last_activity,
		revalidate_after, step_up_acr, step_up_method, step_up_strength, step_up_aaguid, step_up_attachment, step_up_verified_at, step_up_expires_at,
		session_max_age_seconds, revalidate_every_seconds,
		revoke_on_posture_change, revoked
		FROM sessions
		WHERE user_id = ?
		  AND device_id = ?
		  AND resource = ?
		  AND gateway_id = ?
		  AND organization_id = ?
		  AND source_ip = ?
		  AND lower(protocol) = lower(?)
		  AND revoked = 0
		  AND expires_at > ?
		ORDER BY expires_at DESC
		LIMIT 1`,
		strings.TrimSpace(req.UserID),
		strings.TrimSpace(req.DeviceID),
		strings.TrimSpace(req.Resource),
		strings.TrimSpace(req.GatewayID),
		strings.TrimSpace(req.OrganizationID),
		strings.TrimSpace(req.SourceIP),
		strings.TrimSpace(req.Protocol),
		fmtTime(now))
	session, err := scanSession(row)
	if err != nil {
		return nil, false
	}
	return session, true
}

func (s *Store) scanSessions(rows *sql.Rows) []*models.Session {
	var sessions []*models.Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			continue
		}
		sessions = append(sessions, sess)
	}
	return sessions
}

func scanSession(scanner sessionScanner) (*models.Session, error) {
	sess := &models.Session{}
	var revoked, revokeOnPostureChange int
	var createdAt, expiresAt, lastActivity, revalidateAfter, riskSignalsJSON, stepUpVerifiedAt, stepUpExpiresAt string

	err := scanner.Scan(&sess.ID, &sess.UserID, &sess.Username, &sess.DeviceID, &sess.SourceIP,
		&sess.Resource, &sess.GatewayID, &sess.Protocol, &riskSignalsJSON, &sess.OrganizationID, &sess.PolicyID,
		&createdAt, &expiresAt, &lastActivity, &revalidateAfter, &sess.StepUpACR, &sess.StepUpMethod,
		&sess.StepUpStrength, &sess.StepUpAAGUID, &sess.StepUpAttachment, &stepUpVerifiedAt, &stepUpExpiresAt, &sess.SessionMaxAgeSeconds,
		&sess.RevalidateEverySeconds, &revokeOnPostureChange, &revoked)
	if err != nil {
		return nil, err
	}

	sess.Revoked = i2b(revoked)
	sess.RevokeOnPostureChange = i2b(revokeOnPostureChange)
	sess.RiskSignals = fromJSON[[]string](riskSignalsJSON)
	sess.CreatedAt = parseTime(createdAt)
	sess.ExpiresAt = parseTime(expiresAt)
	sess.LastActivity = parseTime(lastActivity)
	sess.RevalidateAfter = parseTime(revalidateAfter)
	sess.StepUpVerifiedAt = parseTime(stepUpVerifiedAt)
	sess.StepUpExpiresAt = parseTime(stepUpExpiresAt)
	return sess, nil
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
		gateway_id, protocol, risk_signals_json, organization_id, policy_id, created_at, expires_at, last_activity,
		revalidate_after, step_up_acr, step_up_method, step_up_strength, step_up_aaguid, step_up_attachment, step_up_verified_at, step_up_expires_at,
		session_max_age_seconds, revalidate_every_seconds,
		revoke_on_posture_change, revoked
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
