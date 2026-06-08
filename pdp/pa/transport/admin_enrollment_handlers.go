package transport

import (
	"errors"
	"log"
	"net/http"
	"strings"

	"pdp/models"
	paenrollment "pdp/pa/enrollment"
)

func (s *Server) handleAdminEnrollments(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	enrollments, err := s.pa.Enrollment.ListDeviceEnrollments()
	if err != nil {
		log.Printf("[ENROLL] Failed to list device enrollments: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list enrollments"})
		return
	}
	enrollments = filterEnrollmentsByOrganization(enrollments, s.allowedOrganizationIDs(r))
	writeJSON(w, http.StatusOK, enrollments)
}

func (s *Server) handleAdminEnrollmentAction(w http.ResponseWriter, r *http.Request) {
	// Parse: /api/admin/enrollments/{id}/{action}
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/enrollments/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expected /api/admin/enrollments/{id}/{action}"})
		return
	}
	enrollmentID := parts[0]
	action := parts[1]

	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	adminUser := r.Header.Get("X-Username")
	enrollment, found := s.pa.Store.GetDeviceEnrollment(enrollmentID)
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "enrollment not found"})
		return
	}
	if !s.requireOrganizationAccess(w, r, enrollment.TenantID) {
		return
	}

	switch action {
	case "approve":
		caPEM, err := s.getCAPEM()
		if err != nil {
			log.Printf("[ENROLL] Failed to get CA PEM for %s: %v", enrollmentID, err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load CA certificate"})
			return
		}

		enrollment, certPEM, err := s.pa.Enrollment.ApprovePendingEnrollment(enrollmentID, adminUser)
		if err != nil {
			s.writeAdminEnrollmentActionError(w, enrollmentID, action, err)
			return
		}

		s.pa.Audit.LogEvent("enrollment_approved", "", adminUser,
			stepUpRemoteIP(r), enrollment.DeviceID, models.DecisionAllow, "Device enrollment approved", true)

		log.Printf("[ENROLL] Approved: id=%s device=%s by=%s", enrollmentID, enrollment.DeviceID, adminUser)

		writeJSON(w, http.StatusOK, models.EnrollmentResponse{
			ID:      enrollmentID,
			Status:  "approved",
			CertPEM: string(certPEM),
			CAPEM:   string(caPEM),
			Message: "Certificate issued",
		})

	case "revoke":
		enrollment, err := s.pa.Enrollment.RevokeDeviceEnrollment(enrollmentID)
		if err != nil {
			s.writeAdminEnrollmentActionError(w, enrollmentID, action, err)
			return
		}

		s.pa.Audit.LogEvent("enrollment_revoked", "", adminUser,
			stepUpRemoteIP(r), enrollment.DeviceID, models.DecisionDeny, "Device enrollment revoked", true)

		log.Printf("[ENROLL] Revoked: id=%s device=%s by=%s", enrollmentID, enrollment.DeviceID, adminUser)

		writeJSON(w, http.StatusOK, models.EnrollmentResponse{
			ID:      enrollmentID,
			Status:  "revoked",
			Message: "Device enrollment revoked",
		})

	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown action: " + action + " (expected: approve, revoke)"})
	}
}

func filterEnrollmentsByOrganization(enrollments []*models.DeviceEnrollment, allowed map[string]bool) []*models.DeviceEnrollment {
	filtered := make([]*models.DeviceEnrollment, 0, len(enrollments))
	for _, enrollment := range enrollments {
		if enrollment != nil && organizationAllowed(allowed, enrollment.TenantID) {
			filtered = append(filtered, enrollment)
		}
	}
	return filtered
}

func (s *Server) writeAdminEnrollmentActionError(w http.ResponseWriter, enrollmentID, action string, err error) {
	switch {
	case errors.Is(err, paenrollment.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "enrollment not found"})
	case errors.Is(err, paenrollment.ErrInvalidRequest), errors.Is(err, paenrollment.ErrInvalidState):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": enrollmentClientMessage(err)})
	case errors.Is(err, paenrollment.ErrInvalidCSR):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid CSR"})
	case errors.Is(err, paenrollment.ErrForbidden):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": enrollmentClientMessage(err)})
	case errors.Is(err, paenrollment.ErrSigning):
		log.Printf("[ENROLL] Failed to sign CSR for %s: %v", enrollmentID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to sign certificate"})
	default:
		log.Printf("[ENROLL] Failed admin enrollment action %s for %s: %v", action, enrollmentID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to process enrollment action"})
	}
}
