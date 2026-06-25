package store

import (
	"log"
	"time"

	"pdp/models"
)

func (s *Store) ReplaceMFARecoveryCodes(userID string, codes []*models.MFARecoveryCode) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.Exec(`DELETE FROM mfa_recovery_codes WHERE user_id = ?`, userID); err != nil {
		return err
	}
	for _, code := range codes {
		if code == nil {
			continue
		}
		if _, err = tx.Exec(
			`INSERT INTO mfa_recovery_codes (id, user_id, code_hash, created_at, used_at)
			 VALUES (?, ?, ?, ?, ?)`,
			code.ID, code.UserID, code.CodeHash, fmtTime(code.CreatedAt), fmtTime(code.UsedAt),
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListActiveMFARecoveryCodes(userID string) ([]*models.MFARecoveryCode, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, code_hash, created_at, used_at
		 FROM mfa_recovery_codes WHERE user_id = ? AND used_at = '' ORDER BY created_at, id`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var codes []*models.MFARecoveryCode
	for rows.Next() {
		code := &models.MFARecoveryCode{}
		var createdAt, usedAt string
		if err := rows.Scan(&code.ID, &code.UserID, &code.CodeHash, &createdAt, &usedAt); err != nil {
			log.Printf("[STORE] Failed to scan MFA recovery code: %v", err)
			continue
		}
		code.CreatedAt = parseTime(createdAt)
		code.UsedAt = parseTime(usedAt)
		codes = append(codes, code)
	}
	return codes, nil
}

func (s *Store) MarkMFARecoveryCodeUsed(id string, usedAt time.Time) bool {
	if usedAt.IsZero() {
		usedAt = time.Now().UTC()
	}
	result, err := s.db.Exec(
		`UPDATE mfa_recovery_codes SET used_at = ? WHERE id = ? AND used_at = ''`,
		fmtTime(usedAt), id,
	)
	if err != nil {
		log.Printf("[STORE] Failed to mark MFA recovery code used: %v", err)
		return false
	}
	affected, err := result.RowsAffected()
	return err == nil && affected == 1
}
