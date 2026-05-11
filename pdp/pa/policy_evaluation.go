package pa

import (
	"strings"
	"time"

	"pdp/models"
	"pdp/pe/evaluation"
)

// EvaluateAccess is the PA-to-PE boundary. PA gathers operational state and
// passes a normalized, side-effect-free context into the Policy Engine.
func (pa *PolicyAdministrator) EvaluateAccess(req models.AccessRequest) *models.AccessDecision {
	if pa == nil || pa.Engine == nil {
		return &models.AccessDecision{
			Decision:  "deny",
			Reason:    "Policy Engine unavailable",
			RiskScore: 100,
		}
	}

	if pa.Store != nil {
		if user, ok := pa.Store.GetUser(req.UserID); ok && user != nil {
			if req.TenantID == "" {
				req.TenantID = user.TenantID
			} else if user.TenantID != "" && !strings.EqualFold(req.TenantID, user.TenantID) {
				return denyTenantMismatch("user does not belong to requested tenant")
			}
		}
		if resource, ok := pa.Store.GetResource(req.Resource); ok && resource != nil {
			if req.TenantID == "" {
				req.TenantID = resource.TenantID
			} else if resource.TenantID != "" && !strings.EqualFold(req.TenantID, resource.TenantID) {
				return denyTenantMismatch("resource does not belong to requested tenant")
			}
			if req.GatewayID == "" {
				req.GatewayID = resource.GatewayID
			} else if resource.GatewayID != "" && !strings.EqualFold(req.GatewayID, resource.GatewayID) {
				return denyTenantMismatch("resource is not assigned to requested gateway")
			}
		}
	}

	ctx := evaluation.AccessContext{
		Request: req,
		Now:     time.Now(),
	}

	if pa.Store != nil {
		if strings.TrimSpace(req.TenantID) != "" || strings.TrimSpace(req.GatewayID) != "" || strings.TrimSpace(req.Resource) != "" {
			ctx.Rules = pa.Store.ListPolicyRulesForAccess(req.TenantID, req.GatewayID, req.Resource)
		} else {
			ctx.Rules = pa.Store.ListPolicyRules()
		}
		ctx.FailedAttempts = pa.Store.GetFailedAttempts(req.Username)
		if user, ok := pa.Store.GetUser(req.UserID); ok && user != nil {
			ctx.UserRole = user.Role
		}
	}

	if pa.Geo != nil && strings.TrimSpace(req.SourceIP) != "" && strings.TrimSpace(req.UserID) != "" {
		geoResult := pa.Geo.CheckImpossibleTravel(req.UserID, req.SourceIP)
		ctx.GeoVelocity = geoResult.SpeedKmH
		ctx.IsImpossibleTravel = geoResult.IsImpossible
	}

	return pa.Engine.Evaluate(ctx)
}

func denyTenantMismatch(reason string) *models.AccessDecision {
	return &models.AccessDecision{
		Decision:  "deny",
		Reason:    reason,
		RiskScore: 100,
	}
}
