package models

import "time"

// DirectoryUser is a user mirrored from an external directory provider through SCIM.
type DirectoryUser struct {
	ID             string            `json:"id"`
	OrganizationID string            `json:"organization_id"`
	IdPID          string            `json:"idp_id"`
	ExternalID     string            `json:"external_id,omitempty"`
	UserName       string            `json:"user_name"`
	DisplayName    string            `json:"display_name,omitempty"`
	Email          string            `json:"email,omitempty"`
	Active         bool              `json:"active"`
	Attributes     map[string]string `json:"attributes,omitempty"`
	RawJSON        string            `json:"raw_json,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

// DirectoryGroup is a group mirrored from an external directory provider
// through SCIM.
type DirectoryGroup struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	IdPID          string    `json:"idp_id"`
	ExternalID     string    `json:"external_id,omitempty"`
	DisplayName    string    `json:"display_name"`
	RawJSON        string    `json:"raw_json,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// DirectoryGroupMember links a SCIM directory group to a SCIM directory user.
type DirectoryGroupMember struct {
	OrganizationID string    `json:"organization_id"`
	IdPID          string    `json:"idp_id"`
	GroupID        string    `json:"group_id"`
	UserID         string    `json:"user_id"`
	CreatedAt      time.Time `json:"created_at"`
}
