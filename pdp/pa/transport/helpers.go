package transport

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"pdp/config"
	paenrollment "pdp/pa/enrollment"
	"pdp/pa/events"
	"pdp/util"
)

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

func (s *Server) caepPayload(eventType string, fields map[string]string) map[string]string {
	now := time.Now().UTC()
	eventID, err := util.GenerateID("caep")
	if err != nil {
		eventID = fmt.Sprintf("caep_%d", now.UnixNano())
	}
	payload := map[string]string{
		"event_id":   eventID,
		"event_type": eventType,
		"changed_at": now.Format(time.RFC3339Nano),
	}
	for key, value := range fields {
		if strings.TrimSpace(value) != "" {
			payload[key] = value
		}
	}
	return payload
}

func (s *Server) publishCAEPEvent(eventType string, fields map[string]string) {
	if s == nil || s.events == nil {
		return
	}
	now := time.Now().UTC()
	s.events.Publish(eventType, events.Event{
		Type:    eventType,
		Time:    now,
		Payload: s.caepPayload(eventType, fields),
	})
}

func (s *Server) PublishCAEPEvent(eventType string, fields map[string]string) {
	s.publishCAEPEvent(eventType, fields)
}

func (s *Server) appConfig() *config.Config {
	if s != nil && s.pa != nil && s.pa.Cfg != nil {
		return s.pa.Cfg
	}
	panic("PDP config is required")
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// writeError logs the real error server-side and returns a sanitized message to the client.
func writeError(w http.ResponseWriter, status int, userMsg string, err error) {
	log.Printf("[ERROR] %s: %v", userMsg, err)
	writeJSON(w, status, map[string]string{"error": userMsg})
}

func (s *Server) getCAPEM() ([]byte, error) {
	if len(s.externalCAPEM) > 0 {
		return s.externalCAPEM, nil
	}
	return nil, fmt.Errorf("CA not initialized")
}

func (s *Server) signerReady() bool {
	return s.externalPKI != nil
}

func normalizeEnrollmentComponent(component string) string {
	return paenrollment.NormalizeComponent(component)
}

func (s *Server) deviceRole(_ string) string {
	return s.pa.Cfg.PKIRoleDevice
}

func (s *Server) signCSR(csrPEM []byte, validDays int, vaultRole string) ([]byte, error) {
	if s.externalPKI != nil {
		ttl := fmt.Sprintf("%dh", validDays*24)
		if strings.TrimSpace(vaultRole) == strings.TrimSpace(s.pa.Cfg.PKIRoleDevice) {
			return s.externalPKI.SignCSRVerbatim(csrPEM, vaultRole, ttl)
		}
		return s.externalPKI.SignCSR(csrPEM, vaultRole, ttl)
	}
	return nil, fmt.Errorf("PKI signer not initialized")
}

func (s *Server) revokeCertificate(serial, certPEM, subjectID string, expiresOn time.Time) {
	if strings.TrimSpace(serial) == "" && strings.TrimSpace(certPEM) == "" {
		return
	}

	if s.externalPKI != nil {
		if err := s.externalPKI.RevokeCertificate(serial, []byte(certPEM)); err != nil {
			log.Printf("[PKI] Failed to revoke certificate in Vault (subject=%s serial=%s): %v", subjectID, serial, err)
		}
	}

	if strings.TrimSpace(serial) != "" {
		s.pa.Store.RevokeCertSerial(serial, subjectID, expiresOn)
		s.publishCAEPEvent(events.TopicRevocation, map[string]string{
			"cert_serial": serial,
			"serial":      serial,
			"subject":     subjectID,
			"reason":      "certificate_revoked",
		})
	}
}
