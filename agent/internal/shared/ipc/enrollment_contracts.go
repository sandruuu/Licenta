package ipc

import "time"

type StartEnrollmentRequest struct {
	AccessToken          string    `json:"access_token,omitempty"`
	AccessTokenExpiresAt time.Time `json:"access_token_expires_at,omitempty"`
	Nonce                string    `json:"nonce"`
	DeviceID             string    `json:"device_id"`
	UserSID              string    `json:"user_sid"`
	KeyName              string    `json:"key_name"`
	UserEmail            string    `json:"user_email,omitempty"`
	SentAt               time.Time `json:"sent_at"`
}

type StartEnrollmentResponse struct {
	Accepted        bool            `json:"accepted"`
	Message         string          `json:"message,omitempty"`
	DeviceID        string          `json:"device_id,omitempty"`
	ActiveUserSID   string          `json:"active_user_sid,omitempty"`
	KeyName         string          `json:"key_name,omitempty"`
	ReceivedAt      time.Time       `json:"received_at"`
	EnrollmentState EnrollmentState `json:"enrollment_state"`
}

type UpdateAccessTokenRequest struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
	DeviceID    string    `json:"device_id"`
	UserSID     string    `json:"user_sid"`
	SentAt      time.Time `json:"sent_at"`
}

type UpdateAccessTokenResponse struct {
	Accepted   bool      `json:"accepted"`
	DeviceID   string    `json:"device_id,omitempty"`
	UserSID    string    `json:"user_sid,omitempty"`
	ExpiresAt  time.Time `json:"expires_at"`
	ReceivedAt time.Time `json:"received_at"`
}
