package transport

import (
	"net/http"
	"strings"

	"pdp/models"
)

func currentAdminUserID(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.Header.Get("X-User-ID"))
}

func (s *Server) canAccessOrganization(r *http.Request, organizationID string) bool {
	if s == nil || s.pa == nil || s.pa.Store == nil {
		return false
	}
	return s.pa.Store.UserHasOrganizationAccess(currentAdminUserID(r), organizationID)
}

func (s *Server) requireOrganizationAccess(w http.ResponseWriter, r *http.Request, organizationID string) bool {
	if strings.TrimSpace(organizationID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "organization_id is required"})
		return false
	}
	if !s.canAccessOrganization(r, organizationID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "organization access denied"})
		return false
	}
	return true
}

func (s *Server) allowedOrganizationIDs(r *http.Request) map[string]bool {
	if s == nil || s.pa == nil || s.pa.Store == nil {
		return map[string]bool{}
	}
	return s.pa.Store.ListOrganizationIDsForUser(currentAdminUserID(r))
}

func organizationAllowed(allowed map[string]bool, organizationID string) bool {
	return allowed[strings.TrimSpace(organizationID)]
}

func filterResourcesByOrganization(resources []*models.Resource, allowed map[string]bool) []*models.Resource {
	filtered := make([]*models.Resource, 0, len(resources))
	for _, resource := range resources {
		if resource != nil && organizationAllowed(allowed, resource.OrganizationID) {
			filtered = append(filtered, resource)
		}
	}
	return filtered
}

func filterDeviceDataByOrganization(reports []*models.DeviceDataReport, allowed map[string]bool) []*models.DeviceDataReport {
	filtered := make([]*models.DeviceDataReport, 0, len(reports))
	for _, report := range reports {
		if report != nil && organizationAllowed(allowed, report.OrganizationID) {
			filtered = append(filtered, report)
		}
	}
	return filtered
}

func filterSessionsByOrganization(sessions []*models.Session, allowed map[string]bool) []*models.Session {
	filtered := make([]*models.Session, 0, len(sessions))
	for _, session := range sessions {
		if session != nil && organizationAllowed(allowed, session.OrganizationID) {
			filtered = append(filtered, session)
		}
	}
	return filtered
}

func filterAuditByOrganization(entries []*models.AuditEntry, allowed map[string]bool) []*models.AuditEntry {
	filtered := make([]*models.AuditEntry, 0, len(entries))
	for _, entry := range entries {
		if entry != nil && (strings.TrimSpace(entry.OrganizationID) == "" || organizationAllowed(allowed, entry.OrganizationID)) {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}
