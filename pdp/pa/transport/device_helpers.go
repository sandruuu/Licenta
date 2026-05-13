package transport

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"pdp/pa/auth"
	"pdp/pa/catalog"
	"pdp/pa/devices"
)

func statusCodeForDeviceTelemetryError(err error) int {
	switch {
	case errors.Is(err, devices.ErrDeviceIDRequired):
		return http.StatusBadRequest
	case errors.Is(err, devices.ErrDeviceIDMismatch):
		return http.StatusForbidden
	case errors.Is(err, devices.ErrNoPriorHealthReport):
		return http.StatusPreconditionRequired
	case errors.Is(err, devices.ErrNoPriorPosture):
		return http.StatusPreconditionFailed
	case errors.Is(err, devices.ErrServiceUnavailable):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// We deliberately do NOT accept any payload body — heartbeats must be
func (s *Server) validateDeviceCatalogToken(token, deviceID string) (*auth.CustomClaims, int, error) {
	if s == nil || s.pa == nil {
		return nil, http.StatusServiceUnavailable, fmt.Errorf("identity services are not available")
	}
	claims, err := s.pa.ValidateDeviceUserToken(token, deviceID)
	if err != nil {
		return nil, httpStatusForAccessError(err), err
	}
	return claims, 0, nil
}

func (s *Server) deviceCatalogSnapshot(claims *auth.CustomClaims) catalog.Snapshot {
	if claims == nil || s == nil || s.pa == nil || s.pa.Catalog == nil {
		return catalog.EmptySnapshot()
	}
	if s.pa.Store == nil {
		return catalog.EmptySnapshot()
	}
	user, ok := s.pa.Store.GetUser(claims.UserID)
	if !ok || user == nil || strings.TrimSpace(user.TenantID) == "" {
		return catalog.EmptySnapshot()
	}
	if tenant, found := s.pa.Store.GetTenant(user.TenantID); !found || tenant == nil || !tenant.Enabled {
		return catalog.EmptySnapshot()
	}
	role := claims.Role
	if strings.TrimSpace(user.Role) != "" {
		role = user.Role
	}
	return s.pa.Catalog.BuildForTenantRole(user.TenantID, role)
}
