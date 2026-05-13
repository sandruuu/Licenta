package models

// LoginRequest represents the primary authentication request.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse is returned after primary authentication succeeds.
type LoginResponse struct {
	Status     string   `json:"status"`
	Message    string   `json:"message"`
	AuthToken  string   `json:"auth_token,omitempty"`
	UserID     string   `json:"user_id"`
	MFAMethods []string `json:"mfa_methods,omitempty"`
}

// MFAVerifyRequest is sent to complete the MFA step-up during resource access.
type MFAVerifyRequest struct {
	MFAToken string `json:"mfa_token"`
	Method   string `json:"method"`
	TOTPCode string `json:"totp_code,omitempty"`
}

// MFAVerifyResponse is returned after successful MFA verification.
type MFAVerifyResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	AuthToken string `json:"auth_token,omitempty"`
}

// MFAStepUpRequest starts MFA for an existing auth token.
type MFAStepUpRequest struct {
	AuthToken     string `json:"auth_token"`
	OIDCSessionID string `json:"oidc_session_id,omitempty"`
}

// MFAStepUpResponse tells the client which MFA methods are available.
type MFAStepUpResponse struct {
	Status     string   `json:"status"`
	Message    string   `json:"message"`
	MFAToken   string   `json:"mfa_token,omitempty"`
	MFAMethods []string `json:"mfa_methods,omitempty"`
}

// MFAEnrollResponse is returned when enrolling in MFA.
type MFAEnrollResponse struct {
	Secret    string `json:"secret"`
	QRCodeURL string `json:"qr_code_url"`
	Message   string `json:"message"`
}

// RegisterRequest represents a new user registration.
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}
