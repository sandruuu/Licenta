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

	ctx := evaluation.AccessContext{
		Request: req,
		Now:     time.Now(),
	}

	if pa.Store != nil {
		ctx.Rules = pa.Store.ListPolicyRules()
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
