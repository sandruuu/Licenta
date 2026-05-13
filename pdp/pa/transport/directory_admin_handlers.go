package transport

import (
	"net/http"
	"strings"
	"time"

	"pdp/models"
)

type adminDirectoryUser struct {
	ID          string            `json:"id"`
	TenantID    string            `json:"tenant_id"`
	IdPID       string            `json:"idp_id"`
	ExternalID  string            `json:"external_id,omitempty"`
	UserName    string            `json:"user_name"`
	DisplayName string            `json:"display_name,omitempty"`
	Email       string            `json:"email,omitempty"`
	Active      bool              `json:"active"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type adminDirectoryGroup struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	IdPID       string    `json:"idp_id"`
	ExternalID  string    `json:"external_id,omitempty"`
	DisplayName string    `json:"display_name"`
	MemberIDs   []string  `json:"member_ids"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (s *Server) handleAdminDirectoryUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s == nil || s.pa == nil || s.pa.Store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "directory store unavailable"})
		return
	}

	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	idpID := strings.TrimSpace(r.URL.Query().Get("idp_id"))
	users := s.pa.Store.ListDirectoryUsersFiltered(tenantID, idpID)

	response := make([]adminDirectoryUser, 0, len(users))
	for _, user := range users {
		if user == nil {
			continue
		}
		response = append(response, adminDirectoryUser{
			ID:          user.ID,
			TenantID:    user.TenantID,
			IdPID:       user.IdPID,
			ExternalID:  user.ExternalID,
			UserName:    user.UserName,
			DisplayName: user.DisplayName,
			Email:       user.Email,
			Active:      user.Active,
			Attributes:  user.Attributes,
			CreatedAt:   user.CreatedAt,
			UpdatedAt:   user.UpdatedAt,
		})
	}

	writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Data: response})
}

func (s *Server) handleAdminDirectoryGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if s == nil || s.pa == nil || s.pa.Store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "directory store unavailable"})
		return
	}

	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	idpID := strings.TrimSpace(r.URL.Query().Get("idp_id"))
	groups := s.pa.Store.ListDirectoryGroupsFiltered(tenantID, idpID)

	response := make([]adminDirectoryGroup, 0, len(groups))
	for _, group := range groups {
		if group == nil {
			continue
		}
		members := s.pa.Store.ListDirectoryGroupMembers(group.TenantID, group.IdPID, group.ID)
		memberIDs := make([]string, 0, len(members))
		for _, member := range members {
			if member != nil && strings.TrimSpace(member.UserID) != "" {
				memberIDs = append(memberIDs, member.UserID)
			}
		}
		response = append(response, adminDirectoryGroup{
			ID:          group.ID,
			TenantID:    group.TenantID,
			IdPID:       group.IdPID,
			ExternalID:  group.ExternalID,
			DisplayName: group.DisplayName,
			MemberIDs:   memberIDs,
			CreatedAt:   group.CreatedAt,
			UpdatedAt:   group.UpdatedAt,
		})
	}

	writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Data: response})
}
