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

// Admin endpoints

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

type adminAccountResponse struct {
	ID                string   `json:"id"`
	Username          string   `json:"username"`
	Email             string   `json:"email"`
	Role              string   `json:"role"`
	MFAEnabled        bool     `json:"mfa_enabled"`
	MFAMethods        []string `json:"mfa_methods"`
	RecoveryCodeCount int      `json:"recovery_code_count"`
	PasswordChangedAt string   `json:"password_changed_at,omitempty"`
	LastLogin         string   `json:"last_login,omitempty"`
}

type adminChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
	ConfirmPassword string `json:"confirm_password"`
}

type adminRegenerateRecoveryCodesRequest struct {
	CurrentPassword string `json:"current_password"`
}

func (s *Server) handleAdminAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	user, ok := s.currentAdminUser(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Data:    s.adminAccountPayload(user),
	})
}

func (s *Server) handleAdminAccountPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	user, ok := s.currentAdminUser(w, r)
	if !ok {
		return
	}
	var req adminChangePasswordRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.NewPassword != req.ConfirmPassword {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password confirmation does not match"})
		return
	}
	if err := s.pa.Auth.Users.ChangePassword(user.ID, req.CurrentPassword, req.NewPassword); err != nil {
		if writePasswordPolicyError(w, http.StatusBadRequest, err) {
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if s.pa.Audit != nil {
		s.pa.Audit.LogEvent("admin_password_changed", user.ID, user.Username, r.RemoteAddr, "", "", "Dashboard password changed", true)
	}
	updated, _ := s.pa.Auth.Users.GetUser(user.ID)
	writeJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Password changed",
		Data:    s.adminAccountPayload(updated),
	})
}

func (s *Server) handleAdminAccountRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	user, ok := s.currentAdminUser(w, r)
	if !ok {
		return
	}
	var req adminRegenerateRecoveryCodesRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if err := s.pa.Auth.Users.VerifyPassword(user.ID, req.CurrentPassword); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	codes, err := s.pa.Auth.Users.GenerateRecoveryCodes(user.ID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if s.pa.Audit != nil {
		s.pa.Audit.LogEvent("admin_recovery_codes_regenerated", user.ID, user.Username, r.RemoteAddr, "", "", "Dashboard recovery codes regenerated", true)
	}
	writeJSON(w, http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Recovery codes regenerated",
		Data: map[string]any{
			"recovery_codes": codes,
		},
	})
}

func (s *Server) currentAdminUser(w http.ResponseWriter, r *http.Request) (*models.User, bool) {
	userID := currentAdminUserID(r)
	if strings.TrimSpace(userID) == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user is not available"})
		return nil, false
	}
	user, exists := s.pa.Auth.Users.GetUser(userID)
	if !exists || user == nil || user.Disabled || user.Role != "platform_admin" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user is not available"})
		return nil, false
	}
	return user, true
}

func (s *Server) adminAccountPayload(user *models.User) adminAccountResponse {
	if user == nil {
		return adminAccountResponse{}
	}
	recoveryCodeCount := 0
	if codes, err := s.pa.Store.ListActiveMFARecoveryCodes(user.ID); err == nil {
		recoveryCodeCount = len(codes)
	}
	payload := adminAccountResponse{
		ID:                user.ID,
		Username:          user.Username,
		Email:             user.Email,
		Role:              user.Role,
		MFAEnabled:        user.MFAEnabled(),
		MFAMethods:        append([]string(nil), user.MFAMethods...),
		RecoveryCodeCount: recoveryCodeCount,
	}
	if !user.PasswordChangedAt.IsZero() {
		payload.PasswordChangedAt = user.PasswordChangedAt.Format("2006-01-02 15:04:05")
	}
	if !user.LastLoginAt.IsZero() {
		payload.LastLogin = user.LastLoginAt.Format("2006-01-02 15:04:05")
	}
	return payload
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
		var organization models.Organization
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&organization); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if organization.ID == "" {
			organization.ID, _ = util.GenerateID("org")
		}
		organization.CreatedAt = time.Now()
		organization.UpdatedAt = time.Now()
		s.pa.Store.SaveOrganization(&organization)
		s.pa.Store.EnsureDefaultGlobalPolicyForOrganization(organization.ID)
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
		organization, found := s.pa.Store.GetOrganization(organizationID)
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "organization not found"})
			return
		}
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Data: organization})

	case http.MethodPut:
		var organization models.Organization
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&organization); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		existing, found := s.pa.Store.GetOrganization(organizationID)
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
		s.pa.Store.SaveOrganization(&organization)
		writeJSON(w, http.StatusOK, models.APIResponse{Success: true, Message: "Organization updated", Data: organization})

	case http.MethodDelete:
		if !s.pa.Store.DeleteOrganization(organizationID) {
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
	if !s.requireOrganizationAccess(w, r, session.OrganizationID) {
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
