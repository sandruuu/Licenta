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
		writeJSON(w, http.StatusOK, items)

	case http.MethodPost:
		var req pagateway.CreateGatewayRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		result, err := s.pa.Gateways.CreateGateway(req)
		if err != nil {
			s.writeGatewayAdminError(w, err)
			return
		}

		log.Printf("[ADMIN] Gateway created: id=%s name=%s auth_mode=%s token_expires=%s", result.Gateway.ID, result.Gateway.Name, result.Gateway.AuthMode, result.Gateway.TokenExpiresAt)

		writeJSON(w, http.StatusCreated, map[string]interface{}{
			"id":               result.Gateway.ID,
			"tenant_id":        result.Gateway.TenantID,
			"name":             result.Gateway.Name,
			"auth_mode":        result.Gateway.AuthMode,
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
		writeJSON(w, http.StatusOK, gw)

	case http.MethodPut:
		var req pagateway.UpdateGatewayRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if _, err := s.pa.Gateways.UpdateGateway(id, req); err != nil {
			s.writeGatewayAdminError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})

	case http.MethodDelete:
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
			result, err := s.pa.Gateways.RegenerateEnrollmentToken(id)
			if err != nil {
				s.writeGatewayAdminError(w, err)
				return
			}

			log.Printf("[ADMIN] Gateway enrollment token regenerated: id=%s", id)

			writeJSON(w, http.StatusOK, map[string]interface{}{
				"id":               result.Gateway.ID,
				"tenant_id":        result.Gateway.TenantID,
				"enrollment_token": result.EnrollmentToken,
				"token_expires_at": result.TokenExpiresAt,
				"message":          "New enrollment token generated (1-hour expiry).",
			})
		} else if action == "revoke" {
			gw, err := s.pa.Gateways.RevokeGateway(id)
			if err != nil {
				s.writeGatewayAdminError(w, err)
				return
			}

			log.Printf("[ADMIN] Gateway revoked: id=%s name=%s", gw.ID, gw.Name)
			writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
		} else if action == "test-federation" {
			// Probe the configured (or supplied) external IdP's discovery doc
			// to validate the issuer is reachable and exposes the required
			// OIDC endpoints. Used by the dashboard "Test connection" button
			// before saving a tenant identity provider configuration.
			if _, found := s.pa.Store.GetGateway(id); !found {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "gateway not found"})
				return
			}
			var req struct {
				Issuer string `json:"issuer,omitempty"`
			}
			_ = json.NewDecoder(io.LimitReader(r.Body, 1<<14)).Decode(&req)
			issuer := strings.TrimSpace(req.Issuer)
			if issuer == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "issuer is required"})
				return
			}
			disc, err := s.pa.Auth.Federation.Discover(issuer)
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]interface{}{
					"ok":     false,
					"issuer": issuer,
					"error":  err.Error(),
				})
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"ok":                     true,
				"issuer":                 issuer,
				"authorization_endpoint": disc.AuthorizationEndpoint,
				"token_endpoint":         disc.TokenEndpoint,
				"userinfo_endpoint":      disc.UserinfoEndpoint,
				"jwks_uri":               disc.JWKSURI,
			})
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown action: " + action})
		}

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}
