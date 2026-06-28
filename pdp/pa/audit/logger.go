package audit

import (
	"log"
	"regexp"
	"strings"
	"time"

	"pdp/models"
	"pdp/store"
	"pdp/util"
)

// AuditLogger provides structured audit logging for security events
type AuditLogger struct {
	store *store.Store
}

var (
	auditDetailsViaURLPattern = regexp.MustCompile(`(?i)\bvia\s+https?://\S+`)
	auditDetailsURLPattern    = regexp.MustCompile(`(?i)\bhttps?://\S+`)
)

// NewAuditLogger creates a new AuditLogger
func NewAuditLogger(s *store.Store) *AuditLogger {
	return &AuditLogger{store: s}
}

// LogEvent records a security event in the audit log
func (al *AuditLogger) LogEvent(eventType, userID, username, sourceIP, resource, decision, details string, success bool) {
	entryID, _ := util.GenerateID("aud")
	details = sanitizeAuditDetails(details)

	entry := &models.AuditEntry{
		ID:        entryID,
		Timestamp: time.Now(),
		EventType: eventType,
		UserID:    strings.TrimSpace(userID),
		Username:  strings.TrimSpace(username),
		SourceIP:  sourceIP,
		Resource:  resource,
		Decision:  decision,
		Details:   details,
		Success:   success,
	}

	al.store.AddAuditEntry(entry)
	log.Printf("[AUDIT] %s: user=%s success=%v details=%s", eventType, username, success, details)
}

func sanitizeAuditDetails(details string) string {
	details = strings.TrimSpace(details)
	switch {
	case strings.HasPrefix(details, "User authenticated for TrustAgent session via"):
		details = "User authenticated via organization sign-in"
	case strings.HasPrefix(details, "Resource step-up requested"):
		details = "Additional verification required for resource access"
	case strings.HasPrefix(details, "Device enrollment requested:"):
		details = "Device enrollment requested"
	case strings.HasPrefix(details, "Device enrollment expired:"):
		details = "Device enrollment expired"
	case strings.HasPrefix(details, "Approved device"):
		details = "Device enrollment approved"
	case strings.HasPrefix(details, "Revoked device"):
		details = "Device enrollment revoked"
	case details == "Raw device data reported":
		details = "Device data received"
	}
	details = auditDetailsViaURLPattern.ReplaceAllString(details, "via organization sign-in")
	details = auditDetailsURLPattern.ReplaceAllString(details, "organization sign-in")
	details = strings.ReplaceAll(details, "PDP ", "")
	details = strings.ReplaceAll(details, " PDP", "")
	details = strings.ReplaceAll(details, "PDP", "")
	details = strings.ReplaceAll(details, "TOTP", "Authenticator app")
	details = strings.ReplaceAll(details, "Auth app", "Authenticator app")
	details = strings.ReplaceAll(details, "WebAuthn", "Passkey")
	details = strings.ReplaceAll(details, "Federated authentication", "Organization sign-in")
	details = strings.ReplaceAll(details, "Federated identity", "Organization sign-in identity")
	details = strings.ReplaceAll(details, "Federated user", "Organization user")
	details = strings.ReplaceAll(details, "external IdP", "organization sign-in")
	details = strings.ReplaceAll(details, "IdP", "organization sign-in")
	return strings.Join(strings.Fields(details), " ")
}

// GetRecentEntries returns the most recent audit entries
func (al *AuditLogger) GetRecentEntries(limit int) []*models.AuditEntry {
	return al.store.GetAuditLog(limit)
}
