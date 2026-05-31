package transport

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"pdp/models"
	"pdp/util"
)

// ─────────────────────────────────────────────
// Admin endpoints
// ─────────────────────────────────────────────

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	users := s.pa.Auth.Users.ListUsers()
	currentUserID := currentAdminUserID(r)

	// Strip sensitive fields
	type safeUser struct {
		ID         string   `json:"id"`
		Username   string   `json:"username"`
		Email      string   `json:"email"`
		MFAEnabled bool     `json:"mfa_enabled"`
		MFAMethods []string `json:"mfa_methods"`
		Role       string   `json:"role"`
		Disabled   bool     `json:"disabled"`
		CreatedAt  string   `json:"created_at"`
		LastLogin  string   `json:"last_login,omitempty"`
	}

	safeUsers := make([]safeUser, 0, len(users))
	for _, u := range users {
		if u == nil || u.ID != currentUserID {
			continue
		}
		su := safeUser{
			ID:         u.ID,
			Username:   u.Username,
			Email:      u.Email,
			MFAEnabled: u.MFAEnabled(),
			MFAMethods: u.MFAMethods,
			Role:       u.Role,
			Disabled:   u.Disabled,
			CreatedAt:  u.CreatedAt.Format("2006-01-02 15:04:05"),
		}
		if !u.LastLoginAt.IsZero() {
			su.LastLogin = u.LastLoginAt.Format("2006-01-02 15:04:05")
		}
		safeUsers = append(safeUsers, su)
	}

	writeJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Data:    safeUsers,
	})
}

func (s *Server) handleAdminOrganizations(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		organizations := s.pa.Store.ListOrganizationsForUser(currentAdminUserID(r))
		writeJSON(w, http.StatusOK, models.APIResponse{
			Success: true,
			Data:    organizations,
		})

	case http.MethodPost:
		var organization models.Tenant
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&organization); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if organization.ID == "" {
			organization.ID, _ = util.GenerateID("org")
		}
		organization.CreatedAt = time.Now()
		organization.UpdatedAt = time.Now()
		s.pa.Store.SaveTenant(&organization)
		s.pa.Store.EnsureDefaultGlobalPolicyForTenant(organization.ID)
		s.pa.Store.SaveOrganizationMembership(&models.OrganizationMembership{
			UserID:         currentAdminUserID(r),
			OrganizationID: organization.ID,
			Role:           "platform_admin",
			CreatedAt:      time.Now(),
		})
		writeJSON(w, http.StatusCreated, models.APIResponse{
			Success: true,
			Message: "Organization created",
			Data:    organization,
		})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleAdminOrganizationByID(w http.ResponseWriter, r *http.Request) {
	organizationID := organizationIDFromAdminPath(r.URL.Path)
	if organizationID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "organization ID required"})
		return
	}
	if !s.requireOrganizationAccess(w, r, organizationID) {
		return
	}

	switch r.Method {
	case http.MethodGet:
		organization, found := s.pa.Store.GetTenant(organizationID)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "organization not found"})
			return
		}
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Data: organization})

	case http.MethodPut:
		var organization models.Tenant
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&organization); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		existing, found := s.pa.Store.GetTenant(organizationID)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "organization not found"})
			return
		}
		organization.ID = organizationID
		organization.CreatedAt = existing.CreatedAt
		if organization.DefaultIdPID == "" {
			organization.DefaultIdPID = existing.DefaultIdPID
		}
		organization.UpdatedAt = time.Now()
		s.pa.Store.SaveTenant(&organization)
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Message: "Organization updated", Data: organization})

	case http.MethodDelete:
		if !s.pa.Store.DeleteTenant(organizationID) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "organization not found"})
			return
		}
		s.pa.Store.DeleteOrganizationMemberships(organizationID)
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Message: "Organization deleted"})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func organizationIDFromAdminPath(path string) string {
	path = strings.TrimSpace(path)
	for _, prefix := range []string{"/api/admin/organizations/"} {
		if strings.HasPrefix(path, prefix) {
			return strings.Trim(strings.TrimPrefix(path, prefix), "/")
		}
	}
	return ""
}

func (s *Server) handleAdminSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	sessions := filterSessionsByOrganization(s.pa.Sessions.ListActiveSessions(), s.allowedOrganizationIDs(r))
	writeJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Data:    sessions,
	})
}

func (s *Server) handleAdminSessionByID(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimPrefix(r.URL.Path, "/api/admin/sessions/")
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session ID required"})
		return
	}

	if r.Method != http.MethodDelete {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	session, found := s.pa.Store.GetSession(sessionID)
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}
	if !s.requireOrganizationAccess(w, r, session.TenantID) {
		return
	}
	if err := s.pa.Sessions.RevokeSession(sessionID); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}

	s.pa.Audit.LogEvent("session_revoked", r.Header.Get("X-User-ID"),
		r.Header.Get("X-Username"), r.RemoteAddr, "", "",
		"Session revoked: "+sessionID, true)

	writeJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Session revoked",
	})
}

func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	limit := 100
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 {
			limit = n
		}
	}

	entries := filterAuditByOrganization(s.pa.Audit.GetRecentEntries(limit), s.allowedOrganizationIDs(r))
	writeJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Data:    entries,
	})
}
