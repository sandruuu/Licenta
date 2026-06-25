package models

import "time"

// WebAuthnCredential stores a WebAuthn credential linked to a user.
type WebAuthnCredential struct {
	ID             string    `json:"id"`
	UserID         string    `json:"user_id"`
	CredentialID   string    `json:"credential_id"`
	CredentialJSON string    `json:"credential_json"`
	Name           string    `json:"name"`
	CreatedAt      time.Time `json:"created_at"`
}

// MFARecoveryCode stores a one-time recovery code hash for an MFA account.
type MFARecoveryCode struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	CodeHash  string    `json:"code_hash"`
	CreatedAt time.Time `json:"created_at"`
	UsedAt    time.Time `json:"used_at,omitempty"`
}

// PushChallenge represents a push-based MFA approval request.
type PushChallenge struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	Username    string    `json:"username"`
	DeviceID    string    `json:"device_id"`
	SourceIP    string    `json:"source_ip"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	RespondedAt time.Time `json:"responded_at,omitempty"`
}
