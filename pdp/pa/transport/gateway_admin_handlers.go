package transport

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	pagateway "pdp/pa/gateway"
)

// ═══════════════════════════════════════════════════════════════════════
// Gateway Enrollment & Management
// ═══════════════════════════════════════════════════════════════════════

func gatewayClientMessage(err error) string {
	message := err.Error()
	for _, prefix := range []string{
		pagateway.ErrInvalidRequest.Error(),
		pagateway.ErrInvalidCSR.Error(),
		pagateway.ErrForbidden.Error(),
	} {
		if strings.HasPrefix(message, prefix+": ") {
			return strings.TrimPrefix(message, prefix+": ")
		}
	}
	return message
}

func (s *Server) writeGatewayAdminError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, pagateway.ErrInvalidRequest):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": gatewayClientMessage(err)})
	case errors.Is(err, pagateway.ErrGatewayNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "gateway not found"})
	case errors.Is(err, pagateway.ErrGatewayTokenGeneration):
		log.Printf("[ADMIN] Gateway token generation failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate gateway token"})
	case errors.Is(err, pagateway.ErrGatewayPersistence):
		log.Printf("[ADMIN] Gateway persistence failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update gateway"})
	default:
		log.Printf("[ADMIN] Gateway operation failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to manage gateway"})
	}
}

// handleAdminGateways handles GET/POST /api/admin/gateways — list or create gateways.
func (s *Server) handleAdminGateways(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.pa.Gateways.ListGatewaySummaries()
		if err != nil {
			s.writeGatewayAdminError(w, err)
			return
		}
		items = filterGatewayItemsByOrganization(items, s.allowedOrganizationIDs(r))
		writeJSON(w, http.StatusOK, items)

	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		var req pagateway.CreateGatewayRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if !s.requireOrganizationAccess(w, r, req.OrganizationID) {
			return
		}
		result, err := s.pa.Gateways.CreateGateway(req)
		if err != nil {
			s.writeGatewayAdminError(w, err)
			return
		}

		log.Printf("[ADMIN] Gateway created: id=%s name=%s token_expires=%s", result.Gateway.ID, result.Gateway.Name, result.Gateway.TokenExpiresAt)

		writeJSON(w, http.StatusCreated, map[string]interface{}{
			"id":               result.Gateway.ID,
			"organization_id":  result.Gateway.OrganizationID,
			"name":             result.Gateway.Name,
			"enrollment_token": result.EnrollmentToken,
			"token_expires_at": result.Gateway.TokenExpiresAt,
			"status":           result.Gateway.Status,
			"message":          "Gateway created. Use the enrollment token to register the gateway within 1 hour.",
		})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// handleAdminGatewayByID handles GET/PUT/DELETE /api/admin/gateways/{id}
func (s *Server) handleAdminGatewayByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/admin/gateways/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "gateway ID required"})
		return
	}

	// Handle action suffixes like /api/admin/gateways/{id}/regenerate-token
	parts := strings.SplitN(id, "/", 2)
	id = parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch r.Method {
	case http.MethodGet:
		gw, err := s.pa.Gateways.GetGatewayForAdmin(id)
		if err != nil {
			s.writeGatewayAdminError(w, err)
			return
		}
		if !s.requireOrganizationAccess(w, r, gw.OrganizationID) {
			return
		}
		writeJSON(w, http.StatusOK, gw)

	case http.MethodPut:
		existing, err := s.pa.Gateways.GetGatewayForAdmin(id)
		if err != nil {
			s.writeGatewayAdminError(w, err)
			return
		}
		if !s.requireOrganizationAccess(w, r, existing.OrganizationID) {
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		var req pagateway.UpdateGatewayRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if strings.TrimSpace(req.OrganizationID) != "" && !s.requireOrganizationAccess(w, r, req.OrganizationID) {
			return
		}
		if _, err := s.pa.Gateways.UpdateGateway(id, req); err != nil {
			s.writeGatewayAdminError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})

	case http.MethodDelete:
		existing, err := s.pa.Gateways.GetGatewayForAdmin(id)
		if err != nil {
			s.writeGatewayAdminError(w, err)
			return
		}
		if !s.requireOrganizationAccess(w, r, existing.OrganizationID) {
			return
		}
		gw, err := s.pa.Gateways.DeleteGateway(id)
		if err != nil {
			s.writeGatewayAdminError(w, err)
			return
		}
		if gw.CertSerial != "" {
			log.Printf("[ADMIN] Revoked cert serial %s for gateway %s before deletion", gw.CertSerial, id)
		}
		log.Printf("[ADMIN] Gateway deleted: id=%s", id)
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	case http.MethodPost:
		// POST with action suffix
		if action == "regenerate-token" {
			existing, err := s.pa.Gateways.GetGatewayForAdmin(id)
			if err != nil {
				s.writeGatewayAdminError(w, err)
				return
			}
			if !s.requireOrganizationAccess(w, r, existing.OrganizationID) {
				return
			}
			result, err := s.pa.Gateways.RegenerateEnrollmentToken(id)
			if err != nil {
				s.writeGatewayAdminError(w, err)
				return
			}

			log.Printf("[ADMIN] Gateway enrollment token regenerated: id=%s", id)

			writeJSON(w, http.StatusOK, map[string]interface{}{
				"id":               result.Gateway.ID,
				"organization_id":  result.Gateway.OrganizationID,
				"enrollment_token": result.EnrollmentToken,
				"token_expires_at": result.TokenExpiresAt,
				"message":          "New enrollment token generated (1-hour expiry).",
			})
		} else if action == "revoke" {
			existing, err := s.pa.Gateways.GetGatewayForAdmin(id)
			if err != nil {
				s.writeGatewayAdminError(w, err)
				return
			}
			if !s.requireOrganizationAccess(w, r, existing.OrganizationID) {
				return
			}
			gw, err := s.pa.Gateways.RevokeGateway(id)
			if err != nil {
				s.writeGatewayAdminError(w, err)
				return
			}

			log.Printf("[ADMIN] Gateway revoked: id=%s name=%s", gw.ID, gw.Name)
			writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown action: " + action})
		}

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func filterGatewayItemsByOrganization(items []pagateway.GatewayListItem, allowed map[string]bool) []pagateway.GatewayListItem {
	filtered := make([]pagateway.GatewayListItem, 0, len(items))
	for _, item := range items {
		if organizationAllowed(allowed, item.OrganizationID) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}
