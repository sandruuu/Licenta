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

func statusCodeForDeviceDataError(err error) int {
	switch {
	case errors.Is(err, devices.ErrDeviceIDRequired):
		return http.StatusBadRequest
	case errors.Is(err, devices.ErrDeviceIDMismatch):
		return http.StatusForbidden
	case errors.Is(err, devices.ErrServiceUnavailable):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func (s *Server) validateDeviceCatalogToken(token, deviceID, certificateThumbprint string) (*auth.CustomClaims, int, error) {
	if s == nil || s.pa == nil {
		return nil, http.StatusServiceUnavailable, fmt.Errorf("identity services are not available")
	}
	claims, err := s.pa.ValidateDeviceUserTokenBoundForScope(token, deviceID, certificateThumbprint, "catalog:read")
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
	if !ok || user == nil || strings.TrimSpace(user.OrganizationID) == "" {
		return catalog.EmptySnapshot()
	}
	if organization, found := s.pa.Store.GetOrganization(user.OrganizationID); !found || organization == nil || !organization.Enabled {
		return catalog.EmptySnapshot()
	}
	if strings.TrimSpace(user.Role) == "" {
		user.Role = claims.Role
	}
	directory := s.pa.DirectoryContextForUser(user)
	if directory.Found && !directory.Active {
		return catalog.EmptySnapshot()
	}
	return s.pa.Catalog.BuildForOrganizationUser(user.OrganizationID, user, directory.GroupIDs, directory.GroupNames)
}
