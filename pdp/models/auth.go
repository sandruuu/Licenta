package models

// LoginRequest represents the primary authentication request.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse is returned after primary authentication succeeds.
type LoginResponse struct {
	Status      string `json:"status"`
	Message     string `json:"message"`
	AuthToken   string `json:"auth_token,omitempty"`
	UserID      string `json:"user_id,omitempty"`
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
