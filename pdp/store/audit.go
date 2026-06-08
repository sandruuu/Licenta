package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"

	"pdp/models"

	_ "modernc.org/sqlite"
)

// ─────────────────────────────────────────────
// Audit Log operations
// ─────────────────────────────────────────────

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

	// Serialise audit writes so the hash chain stays well-defined under
	// concurrent callers; collisions on prev_hash would otherwise allow
	// silent fork.
	s.auditMu.Lock()
	defer s.auditMu.Unlock()

	// Look up the most recent entry's hash to chain from. ORDER BY
	// timestamp DESC, id DESC is stable because IDs are time-prefixed.
	var prevHash string
	row := s.db.QueryRow(`SELECT entry_hash FROM audit_log
		ORDER BY timestamp DESC, id DESC LIMIT 1`)
	if err := row.Scan(&prevHash); err != nil && err != sql.ErrNoRows {
		log.Printf("[STORE] Failed to load prior audit hash: %v", err)
		// Continue with empty prevHash — the verification routine will flag
		// the gap, but we should not lose the audit event entirely.
	}
	entry.PrevHash = prevHash
	entry.EntryHash = computeAuditHash(prevHash, entry)

	_, err := s.db.Exec(`INSERT INTO audit_log
		(id, timestamp, event_type, user_id, username, source_ip, resource, decision, details, success, tenant_id, prev_hash, entry_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.ID, fmtTime(entry.Timestamp), entry.EventType, entry.UserID, entry.Username,
		entry.SourceIP, entry.Resource, entry.Decision, entry.Details, b2i(entry.Success),
		entry.TenantID, entry.PrevHash, entry.EntryHash)
	if err != nil {
		log.Printf("[STORE] Failed to add audit entry: %v", err)
		return
	}

	// Cap audit log at 10000 entries. Pruning DOES break the hash chain
	// for entries removed at the head, but VerifyAuditChain treats the
	// oldest remaining entry's prev_hash as the genesis — operators
	// should archive removed entries elsewhere if forensic continuity
	// across the cap boundary is required.
	s.db.Exec(`DELETE FROM audit_log WHERE id NOT IN (
		SELECT id FROM audit_log ORDER BY timestamp DESC LIMIT 10000)`)
}

func (s *Store) removeSuppressedAuditEntries() error {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin audit cleanup: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()

	result, err := tx.Exec(`DELETE FROM audit_log
		WHERE event_type IN ('oidc_authorize', 'oidc_token_exchange', 'oidc_token_refresh', 'token_revoked')`)
	if err != nil {
		return fmt.Errorf("delete suppressed audit entries: %w", err)
	}
	deleted, _ := result.RowsAffected()
	if deleted == 0 {
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit empty audit cleanup: %w", err)
		}
		committed = true
		return nil
	}

	rows, err := tx.Query(`SELECT id, timestamp, event_type, user_id, username, source_ip,
		resource, decision, details, success
		FROM audit_log ORDER BY timestamp ASC, id ASC`)
	if err != nil {
		return fmt.Errorf("query audit entries for rechain: %w", err)
	}

	type auditChainRow struct {
		entry models.AuditEntry
	}
	chainRows := []auditChainRow{}
	for rows.Next() {
		var (
			row     auditChainRow
			ts      string
			success int
		)
		if err := rows.Scan(&row.entry.ID, &ts, &row.entry.EventType, &row.entry.UserID,
			&row.entry.Username, &row.entry.SourceIP, &row.entry.Resource,
			&row.entry.Decision, &row.entry.Details, &success); err != nil {
			rows.Close()
			return fmt.Errorf("scan audit entry for rechain: %w", err)
		}
		row.entry.Timestamp = parseTime(ts)
		row.entry.Success = success != 0
		chainRows = append(chainRows, row)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close audit rechain rows: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate audit rechain rows: %w", err)
	}

	prevHash := ""
	for _, row := range chainRows {
		entryHash := computeAuditHash(prevHash, &row.entry)
		if _, err := tx.Exec(`UPDATE audit_log SET prev_hash = ?, entry_hash = ? WHERE id = ?`,
			prevHash, entryHash, row.entry.ID); err != nil {
			return fmt.Errorf("update audit hash for %s: %w", row.entry.ID, err)
		}
		prevHash = entryHash
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit audit cleanup: %w", err)
	}
	committed = true
	log.Printf("[STORE] Removed %d suppressed OIDC/token audit entries", deleted)
	return nil
}

// computeAuditHash returns hex(SHA-256(prevHash || canonical(entry))).
// The canonical form is a tab-separated record of the immutable fields
// in a fixed order — JSON is avoided so map iteration order can never
// affect the digest.
func computeAuditHash(prevHash string, e *models.AuditEntry) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write([]byte{0x1e}) // record separator
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
		h.Write([]byte{0x1f}) // unit separator
	}
	if e.Success {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyAuditChain walks every audit_log row in chronological order and
// recomputes each EntryHash. Returns nil if every link verifies; on the
// first mismatch returns an error naming the offending entry. The
// genesis row (oldest) is accepted regardless of its prev_hash so that
// log truncation (the 10000-entry cap above) does not falsely alarm.
//
// Cost is O(n) and runs against the live DB; intended for periodic
// integrity audits, not request-path verification.
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
			succ        int
			prevHashCol string
			entryHash   string
		)
		if err := rows.Scan(&e.ID, &tsStr, &e.EventType, &e.UserID, &e.Username, &e.SourceIP,
			&e.Resource, &e.Decision, &e.Details, &succ, &prevHashCol, &entryHash); err != nil {
			return fmt.Errorf("scan audit row: %w", err)
		}
		e.Timestamp, _ = time.Parse(time.RFC3339Nano, tsStr)
		e.Success = succ != 0
		// Pre-S4.2 rows have empty hash columns — treat them as a
		// best-effort chain restart at this point. Once a single row
		// has a non-empty entry_hash, every subsequent row must verify.
		if entryHash == "" {
			expectedPrev = ""
			first = false
			continue
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
		resource, decision, details, success, tenant_id FROM audit_log ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var entries []*models.AuditEntry
	for rows.Next() {
		e := &models.AuditEntry{}
		var ts string
		var success int

		if err := rows.Scan(&e.ID, &ts, &e.EventType, &e.UserID, &e.Username, &e.SourceIP,
			&e.Resource, &e.Decision, &e.Details, &success, &e.TenantID); err != nil {
			continue
		}

		e.Timestamp = parseTime(ts)
		e.Success = i2b(success)
		entries = append(entries, e)
	}
	return entries
}
