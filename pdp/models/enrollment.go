package models

import "time"

// DeviceEnrollment represents a device certificate enrollment request/record.
type DeviceEnrollment struct {
	ID                   string    `json:"id"`
	DeviceID             string    `json:"device_id"`
	Component            string    `json:"component"`
	Hostname             string    `json:"hostname"`
	PublicKeyFingerprint string    `json:"public_key_fingerprint,omitempty"`
	CertFingerprint      string    `json:"cert_fingerprint,omitempty"`
	CertSerial           string    `json:"cert_serial,omitempty"`
	Status               string    `json:"status"`
	CSRPEM               string    `json:"csr_pem,omitempty"`
	CertPEM              string    `json:"cert_pem,omitempty"`
	EnrolledAt           time.Time `json:"enrolled_at"`
	ExpiresAt            time.Time `json:"expires_at,omitempty"`
	ApprovedBy           string    `json:"approved_by,omitempty"`
	UserID               string    `json:"user_id,omitempty"`
	Username             string    `json:"username,omitempty"`
	OrganizationID       string    `json:"organization_id,omitempty"`
}

// EnrollmentRequest is sent by a device agent to request certificate enrollment.
type EnrollmentRequest struct {
	DeviceID             string `json:"device_id"`
	Component            string `json:"component"`
	Hostname             string `json:"hostname"`
	CSRPEM               string `json:"csr_pem"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	KeyProof             string `json:"key_proof,omitempty"`
}

// EnrollmentResponse is returned after enrollment request or approval.
type EnrollmentResponse struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	CertPEM string `json:"cert_pem,omitempty"`
	CAPEM   string `json:"ca_pem,omitempty"`
	Message string `json:"message,omitempty"`
}

// PendingEnrollSession is an ephemeral browser-based enrollment session.
type PendingEnrollSession struct {
	ID                   string    `json:"id"`
	DeviceID             string    `json:"device_id"`
	Component            string    `json:"component"`
	Hostname             string    `json:"hostname"`
	CSRPEM               string    `json:"csr_pem"`
	PublicKeyFingerprint string    `json:"public_key_fingerprint"`
	Status               string    `json:"status"`
	AuthToken            string    `json:"auth_token,omitempty"`
	UserID               string    `json:"user_id,omitempty"`
	Username             string    `json:"username,omitempty"`
	CertPEM              string    `json:"cert_pem,omitempty"`
	CAPEM                string    `json:"ca_pem,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
	ExpiresAt            time.Time `json:"expires_at"`
}
