package admin

import (
	"log"
	"time"

	"cloud/models"
	"cloud/store"
	"cloud/util"
)

// AuditLogger provides structured audit logging for security events
type AuditLogger struct {
	store *store.Store
}

// NewAuditLogger creates a new AuditLogger
func NewAuditLogger(s *store.Store) *AuditLogger {
	return &AuditLogger{store: s}
}

// LogEvent records a security event in the audit log
func (al *AuditLogger) LogEvent(eventType, userID, username, sourceIP, resource, decision, details string, success bool) {
	entryID, _ := util.GenerateID("aud")

	entry := &models.AuditEntry{
		ID:        entryID,
		Timestamp: time.Now(),
		EventType: eventType,
		UserID:    userID,
		Username:  username,
		SourceIP:  sourceIP,
		Resource:  resource,
		Decision:  decision,
		Details:   details,
		Success:   success,
	}

	al.store.AddAuditEntry(entry)
	log.Printf("[AUDIT] %s: user=%s success=%v details=%s", eventType, username, success, details)
}

// GetRecentEntries returns the most recent audit entries
func (al *AuditLogger) GetRecentEntries(limit int) []*models.AuditEntry {
	return al.store.GetAuditLog(limit)
}
