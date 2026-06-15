package models

import "time"

// AuditEntry records a security-relevant action in the PDP.
type AuditEntry struct {
	ID             string    `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	EventType      string    `json:"event_type"`
	UserID         string    `json:"user_id,omitempty"`
	Username       string    `json:"username,omitempty"`
	SourceIP       string    `json:"source_ip,omitempty"`
	Resource       string    `json:"resource,omitempty"`
	Decision       string    `json:"decision,omitempty"`
	Details        string    `json:"details"`
	Success        bool      `json:"success"`
	OrganizationID string    `json:"organization_id,omitempty"`

	PrevHash  string `json:"prev_hash,omitempty"`
	EntryHash string `json:"entry_hash,omitempty"`
}
