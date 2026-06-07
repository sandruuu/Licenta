package models

import "strings"

// LoginRequest represents the primary authentication request.
type LoginRequest struct {
	Email    string `json:"email"`
	Username string `json:"username,omitempty"`
	Password string `json:"password"`
	Purpose  string `json:"purpose,omitempty"`
}

// Identifier returns the email-first login identifier.
func (r LoginRequest) Identifier() string {
	if email := strings.TrimSpace(r.Email); email != "" {
		return email
	}
	return strings.TrimSpace(r.Username)
}

// LoginResponse is returned after primary authentication succeeds.
type LoginResponse struct {
	Status      string `json:"status"`
	Message     string `json:"message"`
	AuthToken   string `json:"auth_token,omitempty"`
	UserID      string `json:"user_id,omitempty"`
	Purpose     string `json:"purpose,omitempty"`
	ChallengeID string `json:"challenge_id,omitempty"`
	MFARequired bool   `json:"mfa_required,omitempty"`
	MFASetup    bool   `json:"mfa_setup,omitempty"`
	Secret      string `json:"secret,omitempty"`
	QRCodeURL   string `json:"qr_code_url,omitempty"`
	QRCodeImage string `json:"qr_code_image,omitempty"`
}

// MFAEnrollResponse is returned when enrolling in MFA.
type MFAEnrollResponse struct {
	Secret      string `json:"secret"`
	QRCodeURL   string `json:"qr_code_url"`
	QRCodeImage string `json:"qr_code_image,omitempty"`
	Message     string `json:"message"`
}

// RegisterRequest represents a new user registration.
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// MFAVerifyRequest completes the second login step for the PDP dashboard.
type MFAVerifyRequest struct {
	ChallengeID string `json:"challenge_id"`
	Code        string `json:"code"`
}
