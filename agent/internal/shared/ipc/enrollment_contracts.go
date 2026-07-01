package ipc

import "time"

type StartEnrollmentInteractiveRequest struct{}

type StartEnrollmentInteractiveResponse struct {
	Started             bool            `json:"started"`
	AuthURL             string          `json:"auth_url,omitempty"`
	EnrollmentSessionID string          `json:"enrollment_session_id,omitempty"`
	State               EnrollmentState `json:"state"`
	Message             string          `json:"message,omitempty"`
	ExpiresAt           time.Time       `json:"expires_at,omitempty"`
	ReportedAt          time.Time       `json:"reported_at"`
}
