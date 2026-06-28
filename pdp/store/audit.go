package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"pdp/models"
)

var suppressedAuditEventTypes = map[string]struct{}{
	"oidc_authorize":      {},
	"oidc_token_exchange": {},
	"oidc_token_refresh":  {},
	"token_revoked":       {},
}

func isSuppressedAuditEvent(eventType string) bool {
	_, ok := suppressedAuditEventTypes[strings.TrimSpace(eventType)]
	return ok
}

func (s *Store) AddAuditEntry(entry *models.AuditEntry) {
	if entry == nil || isSuppressedAuditEvent(entry.EventType) {
		return
	}
	s.resolveAuditUserContext(entry)
	if entry.UserID == "" && entry.Username == "" {
		log.Printf("[STORE] Skipping audit entry without user context: event_type=%s resource=%s", entry.EventType, entry.Resource)
		return
	}

	s.auditMu.Lock()
	defer s.auditMu.Unlock()

	var prevHash string
	row := s.db.QueryRow(`SELECT entry_hash FROM audit_log
		ORDER BY timestamp DESC, id DESC LIMIT 1`)
	if err := row.Scan(&prevHash); err != nil && err != sql.ErrNoRows {
		log.Printf("[STORE] Failed to load prior audit hash: %v", err)
	}
	entry.PrevHash = prevHash
	entry.EntryHash = computeAuditHash(prevHash, entry)

	_, err := s.db.Exec(`INSERT INTO audit_log
		(id, timestamp, event_type, user_id, username, source_ip, resource, decision, details, success, organization_id, prev_hash, entry_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.ID, fmtTime(entry.Timestamp), entry.EventType, entry.UserID, entry.Username,
		entry.SourceIP, entry.Resource, entry.Decision, entry.Details, b2i(entry.Success),
		entry.OrganizationID, entry.PrevHash, entry.EntryHash)
	if err != nil {
		log.Printf("[STORE] Failed to add audit entry: %v", err)
		return
	}

	s.db.Exec(`DELETE FROM audit_log WHERE id NOT IN (
		SELECT id FROM audit_log ORDER BY timestamp DESC LIMIT 10000)`)
}

func (s *Store) resolveAuditUserContext(entry *models.AuditEntry) {
	if entry == nil {
		return
	}
	entry.UserID = strings.TrimSpace(entry.UserID)
	entry.Username = strings.TrimSpace(entry.Username)
	if s == nil {
		return
	}
	if entry.UserID != "" {
		if user, ok := s.GetUser(entry.UserID); ok && user != nil {
			entry.UserID = user.ID
			if strings.TrimSpace(entry.Username) == "" {
				entry.Username = user.Username
			}
			if strings.TrimSpace(entry.OrganizationID) == "" {
				entry.OrganizationID = user.OrganizationID
			}
		}
		return
	}
	if entry.Username == "" {
		return
	}
	if user, ok := s.GetUserByEmail(entry.Username); ok && user != nil {
		entry.UserID = user.ID
		entry.Username = user.Username
		if strings.TrimSpace(entry.OrganizationID) == "" {
			entry.OrganizationID = user.OrganizationID
		}
		return
	}
	if user, ok := s.GetUserByUsername(entry.Username); ok && user != nil {
		entry.UserID = user.ID
		entry.Username = user.Username
		if strings.TrimSpace(entry.OrganizationID) == "" {
			entry.OrganizationID = user.OrganizationID
		}
	}
}

func computeAuditHash(prevHash string, e *models.AuditEntry) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write([]byte{0x1e})
	fields := []string{
		e.ID,
		fmtTime(e.Timestamp),
		e.EventType,
		e.UserID,
		e.Username,
		e.SourceIP,
		e.Resource,
		e.Decision,
		e.Details,
	}
	for _, f := range fields {
		h.Write([]byte(f))
		h.Write([]byte{0x1f})
	}
	if e.Success {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (s *Store) VerifyAuditChain() error {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()

	rows, err := s.db.Query(`SELECT id, timestamp, event_type, user_id, username, source_ip,
		resource, decision, details, success, prev_hash, entry_hash
		FROM audit_log ORDER BY timestamp ASC, id ASC`)
	if err != nil {
		return fmt.Errorf("query audit_log: %w", err)
	}
	defer rows.Close()

	var (
		expectedPrev string
		first        = true
	)
	for rows.Next() {
		var (
			e           models.AuditEntry
			tsStr       string
			success     int
			prevHashCol string
			entryHash   string
		)
		if err := rows.Scan(&e.ID, &tsStr, &e.EventType, &e.UserID, &e.Username, &e.SourceIP,
			&e.Resource, &e.Decision, &e.Details, &success, &prevHashCol, &entryHash); err != nil {
			return fmt.Errorf("scan audit row: %w", err)
		}
		e.Timestamp = parseTime(tsStr)
		e.Success = success != 0
		if entryHash == "" {
			return fmt.Errorf("audit hash missing at id=%s", e.ID)
		}
		if !first && prevHashCol != expectedPrev {
			return fmt.Errorf("audit chain broken at id=%s: prev_hash=%q expected=%q", e.ID, prevHashCol, expectedPrev)
		}
		recomputed := computeAuditHash(prevHashCol, &e)
		if recomputed != entryHash {
			return fmt.Errorf("audit hash mismatch at id=%s: stored=%s computed=%s", e.ID, entryHash, recomputed)
		}
		expectedPrev = entryHash
		first = false
	}
	return rows.Err()
}

func (s *Store) GetAuditLog(limit int) []*models.AuditEntry {
	if limit <= 0 {
		limit = 100
	}

	rows, err := s.db.Query(`SELECT id, timestamp, event_type, user_id, username, source_ip,
		resource, decision, details, success, organization_id FROM audit_log ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var entries []*models.AuditEntry
	for rows.Next() {
		entry := &models.AuditEntry{}
		var ts string
		var success int

		if err := rows.Scan(&entry.ID, &ts, &entry.EventType, &entry.UserID, &entry.Username, &entry.SourceIP,
			&entry.Resource, &entry.Decision, &entry.Details, &success, &entry.OrganizationID); err != nil {
			continue
		}

		entry.Timestamp = parseTime(ts)
		entry.Success = i2b(success)
		entries = append(entries, entry)
	}
	return entries
}
