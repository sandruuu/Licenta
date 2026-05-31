package transport

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"pdp/models"
	paresources "pdp/pa/resources"
)

// ─────────────────────────────────────────────
// PDP Resource management handlers
// ─────────────────────────────────────────────

func writeResourceAdminError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, paresources.ErrInvalidRequest):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": resourceClientMessage(err)})
	case errors.Is(err, paresources.ErrResourceNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "resource not found"})
	default:
		log.Printf("[PDP] Resource operation failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to manage resource"})
	}
}

func resourceClientMessage(err error) string {
	message := err.Error()
	for _, prefix := range []string{paresources.ErrInvalidRequest.Error()} {
		if strings.HasPrefix(message, prefix+": ") {
			return strings.TrimPrefix(message, prefix+": ")
		}
	}
	return message
}

func (s *Server) handleAdminResources(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		resources, err := s.pa.Resources.ListResources()
		if err != nil {
			writeResourceAdminError(w, err)
			return
		}
		resources = filterResourcesByOrganization(resources, s.allowedOrganizationIDs(r))
		writeJSON(w, http.StatusOK, resources)

	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		var res models.Resource
		if err := json.Unmarshal(body, &res); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		applyOrganizationAliasToResource(body, &res)
		if !s.requireOrganizationAccess(w, r, res.TenantID) {
			return
		}
		created, err := s.pa.Resources.CreateResource(res)
		if err != nil {
			writeResourceAdminError(w, err)
			return
		}

		log.Printf("[PDP] Resource created: %s (%s) type=%s host=%s", created.ID, created.Name, created.Type, created.Host)

		writeJSON(w, http.StatusCreated, created)

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleAdminResourceByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/admin/resources/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "resource ID required"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		res, err := s.pa.Resources.GetResource(id)
		if err != nil {
			writeResourceAdminError(w, err)
			return
		}
		if !s.requireOrganizationAccess(w, r, res.TenantID) {
			return
		}
		writeJSON(w, http.StatusOK, res)

	case http.MethodPut:
		existing, err := s.pa.Resources.GetResource(id)
		if err != nil {
			writeResourceAdminError(w, err)
			return
		}
		if !s.requireOrganizationAccess(w, r, existing.TenantID) {
			return
		}
		// Decode into a map to detect which fields were actually sent (PATCH semantics)
		var fields map[string]json.RawMessage
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&fields); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		applyOrganizationAliasToFields(fields)
		if raw, ok := fields["tenant_id"]; ok {
			var targetOrganizationID string
			_ = json.Unmarshal(raw, &targetOrganizationID)
			if strings.TrimSpace(targetOrganizationID) != "" && !s.requireOrganizationAccess(w, r, targetOrganizationID) {
				return
			}
		}
		updated, err := s.pa.Resources.UpdateResource(id, fields)
		if err != nil {
			writeResourceAdminError(w, err)
			return
		}
		log.Printf("[PDP] Resource updated: %s (%s)", updated.ID, updated.Name)
		writeJSON(w, http.StatusOK, updated)

	case http.MethodDelete:
		existing, err := s.pa.Resources.GetResource(id)
		if err != nil {
			writeResourceAdminError(w, err)
			return
		}
		if !s.requireOrganizationAccess(w, r, existing.TenantID) {
			return
		}
		if err := s.pa.Resources.DeleteResource(id); err != nil {
			writeResourceAdminError(w, err)
			return
		}
		log.Printf("[PDP] Resource deleted: %s", id)
		writeJSON(w, http.StatusOK, map[string]string{"message": "resource deleted"})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) handleAdminDeviceData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	reports := filterDeviceDataByOrganization(s.pa.Store.ListDeviceData(), s.allowedOrganizationIDs(r))
	if reports == nil {
		reports = []*models.DeviceDataReport{}
	}
	sort.SliceStable(reports, func(i, j int) bool {
		return reports[i].ReportedAt.After(reports[j].ReportedAt)
	})

	writeJSON(w, http.StatusOK, reports)
}

func (s *Server) handleAdminDeviceDataByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	deviceID := strings.TrimPrefix(r.URL.Path, "/api/admin/device-data/")
	if deviceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device ID required"})
		return
	}

	report, ok := s.pa.Store.GetDeviceData(deviceID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device not found"})
		return
	}
	if !s.requireOrganizationAccess(w, r, report.TenantID) {
		return
	}

	writeJSON(w, http.StatusOK, report)
}

// ─────────────────────────────────────────────
// Dashboard stats endpoint
// ─────────────────────────────────────────────

func (s *Server) handleDashboardStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	allowed := s.allowedOrganizationIDs(r)
	users := s.pa.Store.ListUsers()
	sessions := filterSessionsByOrganization(s.pa.Store.ListSessions(), allowed)
	resources := filterResourcesByOrganization(s.pa.Store.ListResources(), allowed)
	audit := filterAuditByOrganization(s.pa.Store.GetAuditLog(50), allowed)

	activeSessions := 0
	for _, sess := range sessions {
		if !sess.Revoked && !sess.ExpiresAt.Before(time.Now()) {
			activeSessions++
		}
	}

	recentDenials := 0
	for _, entry := range audit {
		if entry.Decision == "deny" {
			recentDenials++
		}
	}

	deviceDataCount := 0
	healthyDevices := 0
	allDeviceData := filterDeviceDataByOrganization(s.pa.Store.ListDeviceData(), allowed)
	for _, report := range allDeviceData {
		deviceDataCount++
		if deviceDataIsHealthy(report) {
			healthyDevices++
		}
	}

	stats := models.DashboardStats{
		TotalUsers:     len(users),
		ActiveSessions: activeSessions,
		TotalResources: len(resources),
		RecentDenials:  recentDenials,
		HealthyDevices: healthyDevices,
		TotalDevices:   deviceDataCount,
	}

	writeJSON(w, http.StatusOK, stats)
}

func deviceDataIsHealthy(report *models.DeviceDataReport) bool {
	if report == nil || len(report.Checks) == 0 {
		return false
	}
	for _, check := range report.Checks {
		switch strings.ToLower(strings.TrimSpace(check.Status)) {
		case "good":
			continue
		default:
			return false
		}
	}
	return true
}

func applyOrganizationAliasToResource(body []byte, resource *models.Resource) {
	if resource == nil || len(body) == 0 {
		return
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return
	}
	if value, ok := raw["organization_id"]; ok && strings.TrimSpace(resource.TenantID) == "" {
		_ = json.Unmarshal(value, &resource.TenantID)
	}
}

func applyOrganizationAliasToFields(fields map[string]json.RawMessage) {
	if fields == nil {
		return
	}
	if value, ok := fields["organization_id"]; ok {
		fields["tenant_id"] = value
	}
}

// ─────────────────────────────────────────────
// Dashboard SPA handler
// ─────────────────────────────────────────────

func (s *Server) handleDashboardSPA(w http.ResponseWriter, r *http.Request) {
	// Serve from pdp/pa/dashboard/dist/ during development or /app/dashboard/dist in containers.
	distDir := findDashboardDir()
	if distDir == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "dashboard not built - run: cd pdp/pa/dashboard && npm run build"})
		return
	}

	// Strip /dashboard/ prefix and sanitize against path traversal
	filePath := strings.TrimPrefix(r.URL.Path, "/dashboard/")
	if filePath == "" {
		filePath = "index.html"
	}

	// Prevent path traversal: clean the path and verify it stays within distDir
	cleanedPath := filepath.Clean(filePath)
	if strings.Contains(cleanedPath, "..") || filepath.IsAbs(cleanedPath) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	fullPath := filepath.Join(distDir, cleanedPath)

	// Double-check: resolved path must be within distDir
	absDistDir, _ := filepath.Abs(distDir)
	absFullPath, _ := filepath.Abs(fullPath)
	if !strings.HasPrefix(absFullPath, absDistDir+string(filepath.Separator)) && absFullPath != absDistDir {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		// SPA fallback: serve index.html for client-side routing
		fullPath = filepath.Join(distDir, "index.html")
	}

	if filepath.Base(fullPath) == "index.html" {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
	}

	http.ServeFile(w, r, fullPath)
}

func (s *Server) serveDashboardIndex(w http.ResponseWriter, r *http.Request) {
	distDir := findDashboardDir()
	if distDir == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "dashboard not built - run: cd pdp/pa/dashboard && npm run build"})
		return
	}
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	http.ServeFile(w, r, filepath.Join(distDir, "index.html"))
}

func findDashboardDir() string {
	candidates := []string{
		"pdp/pa/dashboard/dist",
		"pa/dashboard/dist",
		"../pdp/pa/dashboard/dist",
		"pdp/dashboard/dist",
		"dashboard/dist",
		"../pdp/dashboard/dist",
	}
	// Also check relative to executable
	if execPath, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(execPath), "dashboard", "dist"))
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}
	return ""
}
