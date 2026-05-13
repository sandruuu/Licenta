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
	case errors.Is(err, paresources.ErrCredentialIssue):
		log.Printf("[PDP] Resource credential generation failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate credentials"})
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
		writeJSON(w, http.StatusOK, resources)

	case http.MethodPost:
		var res models.Resource
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&res); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
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
		writeJSON(w, http.StatusOK, res)

	case http.MethodPut:
		// Decode into a map to detect which fields were actually sent (PATCH semantics)
		var fields map[string]json.RawMessage
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&fields); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		updated, err := s.pa.Resources.UpdateResource(id, fields)
		if err != nil {
			writeResourceAdminError(w, err)
			return
		}
		log.Printf("[PDP] Resource updated: %s (%s)", updated.ID, updated.Name)
		writeJSON(w, http.StatusOK, updated)

	case http.MethodDelete:
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

// handleRegenerateSecret generates a new ClientSecret for a resource (ClientID stays the same).
func (s *Server) handleRegenerateSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/admin/resources-regenerate-secret/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "resource ID required"})
		return
	}

	res, err := s.pa.Resources.RegenerateSecret(id)
	if err != nil {
		if errors.Is(err, paresources.ErrCredentialIssue) {
			log.Printf("[PDP] Resource secret generation failed: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate secret"})
			return
		}
		writeResourceAdminError(w, err)
		return
	}

	log.Printf("[PDP] Secret regenerated for resource: %s (%s)", res.ID, res.Name)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"client_id":     res.ClientID,
		"client_secret": res.ClientSecret,
	})
}

func (s *Server) handleAdminDeviceHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	reports := s.pa.Store.ListDeviceHealth()
	if reports == nil {
		reports = []*models.DeviceHealthReport{}
	}
	// Show newest reports first to make recent device activity visible in dashboard.
	sort.SliceStable(reports, func(i, j int) bool {
		return reports[i].ReportedAt.After(reports[j].ReportedAt)
	})

	writeJSON(w, http.StatusOK, reports)
}

func (s *Server) handleAdminDeviceHealthByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	deviceID := strings.TrimPrefix(r.URL.Path, "/api/admin/device-health/")
	if deviceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device ID required"})
		return
	}

	report, ok := s.pa.Store.GetDeviceHealth(deviceID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device not found"})
		return
	}

	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleAdminDevicePosture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	reports := s.pa.Store.ListDevicePosture()
	if reports == nil {
		reports = []*models.DevicePostureReport{}
	}
	sort.SliceStable(reports, func(i, j int) bool {
		return reports[i].ReportedAt.After(reports[j].ReportedAt)
	})

	writeJSON(w, http.StatusOK, reports)
}

func (s *Server) handleAdminDevicePostureByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	deviceID := strings.TrimPrefix(r.URL.Path, "/api/admin/device-posture/")
	if deviceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device ID required"})
		return
	}

	report, ok := s.pa.Store.GetDevicePosture(deviceID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device not found"})
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

	users := s.pa.Store.ListUsers()
	sessions := s.pa.Store.ListSessions()
	resources := s.pa.Store.ListResources()
	rules := s.pa.Store.ListPolicyRules()
	audit := s.pa.Store.GetAuditLog(50)

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

	var totalRisk float64
	healthCount := 0
	healthyDevices := 0
	allDeviceHealth := s.pa.Store.ListDeviceHealth()
	for _, dh := range allDeviceHealth {
		totalRisk += float64(100 - dh.OverallScore)
		healthCount++
		if dh.OverallScore >= 70 {
			healthyDevices++
		}
	}
	avgRisk := 0.0
	if healthCount > 0 {
		avgRisk = totalRisk / float64(healthCount)
	}

	stats := models.DashboardStats{
		TotalUsers:     len(users),
		ActiveSessions: activeSessions,
		TotalResources: len(resources),
		TotalPolicies:  len(rules),
		RecentDenials:  recentDenials,
		AverageRisk:    int(avgRisk),
		HealthyDevices: healthyDevices,
		TotalDevices:   healthCount,
	}

	writeJSON(w, http.StatusOK, stats)
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
