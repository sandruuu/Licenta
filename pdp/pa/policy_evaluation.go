package pa

import (
	"strings"
	"time"

	"pdp/models"
	"pdp/pe/evaluation"
)

const newDeviceWindow = 24 * time.Hour

// EvaluateAccess is the PA-to-PE boundary. PA gathers operational state and
// passes a normalized, side-effect-free context into the Policy Engine.
func (pa *PolicyAdministrator) EvaluateAccess(req models.AccessRequest) *models.AccessDecision {
	return pa.EvaluateAccessWithAuth(req, models.AuthContext{})
}

func (pa *PolicyAdministrator) EvaluateAccessWithAuth(req models.AccessRequest, authCtx models.AuthContext) *models.AccessDecision {
	if pa == nil || pa.Engine == nil {
		return &models.AccessDecision{
			Decision: models.DecisionDeny,
			Reason:   "Policy Engine unavailable",
		}
	}

	var user *models.User
	if pa.Store != nil {
		if foundUser, ok := pa.Store.GetUser(req.UserID); ok && foundUser != nil {
			user = foundUser
			if req.OrganizationID == "" {
				req.OrganizationID = user.OrganizationID
			} else if user.OrganizationID != "" && !strings.EqualFold(req.OrganizationID, user.OrganizationID) {
				return denyOrganizationMismatch("user does not belong to requested organization")
			}
		}
		if resource, ok := pa.Store.GetResource(req.Resource); ok && resource != nil {
			if req.OrganizationID == "" {
				req.OrganizationID = resource.OrganizationID
			} else if resource.OrganizationID != "" && !strings.EqualFold(req.OrganizationID, resource.OrganizationID) {
				return denyOrganizationMismatch("resource does not belong to requested organization")
			}
			if req.GatewayID == "" {
				req.GatewayID = resource.GatewayID
			} else if resource.GatewayID != "" && !strings.EqualFold(req.GatewayID, resource.GatewayID) {
				return denyOrganizationMismatch("resource is not assigned to requested gateway")
			}
		}
	}

	ctx := evaluation.AccessContext{
		Request: req,
		Auth:    authCtx,
		Now:     time.Now(),
	}

	if pa.Store != nil {
		if pa.Runtime != nil {
			ctx.FailedAttempts = pa.Runtime.GetFailedAttempts(req.Username)
		}
		ctx.IsNewDevice = pa.isNewUserDevice(req.UserID, req.DeviceID, ctx.Now)
		if user != nil {
			ctx.UserRole = user.Role
			ctx.UserMFAEnabled = user.MFAEnabled()
			if decision := pa.populateDirectoryContext(&ctx, user); decision != nil {
				return decision
			}
		}
		if strings.TrimSpace(req.OrganizationID) != "" || strings.TrimSpace(req.Resource) != "" {
			ctx.Rules = pa.Store.ListPolicyRulesForAccessGroups(req.OrganizationID, req.Resource, ctx.DirectoryGroupIDs, ctx.DirectoryGroupNames)
		} else {
			ctx.Rules = pa.Store.ListPolicyRules()
		}
	}

	if pa.Geo != nil && strings.TrimSpace(req.SourceIP) != "" && strings.TrimSpace(req.UserID) != "" {
		locationCtx := pa.Geo.CheckAccessLocation(req.UserID, req.SourceIP)
		ctx.GeoVelocity = locationCtx.SpeedKmH
		ctx.IsImpossibleTravel = locationCtx.IsImpossible
		ctx.IsNewLocation = locationCtx.IsNewLocation
		ctx.IsUserBaselineAnomaly = locationCtx.UserBaselineAnomaly
		ctx.SourceLocationKnown = locationCtx.LocationKnown
		ctx.SourceCountry = locationCtx.Country
		ctx.SourceCountryCode = locationCtx.CountryCode
	}

	return pa.Engine.Evaluate(ctx)
}

func (pa *PolicyAdministrator) isNewUserDevice(userID, deviceID string, now time.Time) bool {
	if pa == nil || pa.Store == nil || strings.TrimSpace(userID) == "" || strings.TrimSpace(deviceID) == "" {
		return false
	}
	binding, found := pa.Store.GetDeviceUserBinding(strings.TrimSpace(userID), strings.TrimSpace(deviceID))
	if !found || binding == nil {
		return true
	}
	if binding.BoundAt.IsZero() {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	return now.Sub(binding.BoundAt) <= newDeviceWindow
}

func denyOrganizationMismatch(reason string) *models.AccessDecision {
	return &models.AccessDecision{
		Decision: models.DecisionDeny,
		Reason:   reason,
	}
}
