package models

import "time"

// User represents a registered user in the identity provider.
type User struct {
	ID              string   `json:"id"`
	Username        string   `json:"username"`
	Email           string   `json:"email"`
	PasswordHash    string   `json:"password_hash"`
	TOTPSecret      string   `json:"totp_secret,omitempty"`
	MFAMethods      []string `json:"mfa_methods"`
	Role            string   `json:"role"`
	Disabled        bool     `json:"disabled"`
	TenantID        string   `json:"tenant_id,omitempty"`
	LastTOTPCounter int64    `json:"last_totp_counter,omitempty"`

	ExternalSubject string `json:"external_subject,omitempty"`
	AuthSource      string `json:"auth_source,omitempty"`

	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	LastLoginAt time.Time `json:"last_login_at,omitempty"`
}

// MFAEnabled returns true if the user has at least one MFA method configured.
func (u *User) MFAEnabled() bool {
	return len(u.MFAMethods) > 0
}

// LoginLocation records where a user logged in from.
type LoginLocation struct {
	UserID    string    `json:"user_id"`
	SourceIP  string    `json:"source_ip"`
	Latitude  float64   `json:"latitude"`
	Longitude float64   `json:"longitude"`
	City      string    `json:"city"`
	Country   string    `json:"country"`
	Timestamp time.Time `json:"timestamp"`
}
