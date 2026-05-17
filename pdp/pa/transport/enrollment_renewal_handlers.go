package transport

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"pdp/models"
	paenrollment "pdp/pa/enrollment"
)

// handleCertRenewal handles POST /api/enroll/renew — device agents renew short-lived certs
func (s *Server) handleCertRenewal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	authenticatedEnrollment, ok := deviceEnrollmentFromContext(r)
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "device identity not found in request context"})
		return
	}

	var req models.EnrollmentRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	caPEM, err := s.getCAPEM()
	if err != nil {
		log.Printf("[ENROLL] Renewal: failed to load CA PEM for device %s: %v", req.DeviceID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load CA certificate"})
		return
	}

	enrollment, certPEM, err := s.pa.Enrollment.RenewDeviceCertificate(req, authenticatedEnrollment)
	if err != nil {
		s.writeEnrollmentRenewalError(w, req.DeviceID, err)
		return
	}

	log.Printf("[ENROLL] Renewed cert for device=%s serial=%s", req.DeviceID, enrollment.CertSerial)

	writeJSON(w, http.StatusOK, models.EnrollmentResponse{
		ID:      enrollment.ID,
		Status:  "approved",
		CertPEM: string(certPEM),
		CAPEM:   string(caPEM),
		Message: "Certificate renewed (24h validity)",
	})
}

func (s *Server) writeEnrollmentRenewalError(w http.ResponseWriter, deviceID string, err error) {
	switch {
	case errors.Is(err, paenrollment.ErrInvalidRequest):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": enrollmentClientMessage(err)})
	case errors.Is(err, paenrollment.ErrInvalidCSR):
		log.Printf("[ENROLL] Invalid CSR in renewal for device %s: %v", deviceID, err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid CSR"})
	case errors.Is(err, paenrollment.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": enrollmentClientMessage(err)})
	case errors.Is(err, paenrollment.ErrForbidden):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": enrollmentClientMessage(err)})
	default:
		log.Printf("[ENROLL] Renewal: failed to sign CSR for device %s: %v", deviceID, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to sign certificate"})
	}
}

func enrollmentClientMessage(err error) string {
	message := err.Error()
	for _, prefix := range []string{
		paenrollment.ErrInvalidRequest.Error(),
		paenrollment.ErrForbidden.Error(),
		paenrollment.ErrNotFound.Error(),
		paenrollment.ErrInvalidState.Error(),
		paenrollment.ErrInvalidCSR.Error(),
	} {
		if strings.HasPrefix(message, prefix+": ") {
			return strings.TrimPrefix(message, prefix+": ")
		}
	}
	return message
}
