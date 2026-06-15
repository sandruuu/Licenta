package evaluation

import (
	"fmt"
	"log"
	"time"

	"pdp/config"
	"pdp/models"
	perisk "pdp/pe/risk"
)

// AccessContext is the normalized, side-effect-free input evaluated by PE.
// PA is responsible for loading rules, user attributes, risk signals, and
// device data before calling the engine.
type AccessContext struct {
	Request               models.AccessRequest
	Rules                 []*models.PolicyRule
	Auth                  models.AuthContext
	UserRole              string
	UserEmail             string
	DirectoryUserID       string
	DirectoryUserName     string
	DirectoryGroupIDs     []string
	DirectoryGroupNames   []string
	FailedAttempts        int
	UserMFAEnabled        bool
	SourceCountry         string
	SourceCountryCode     string
	SourceLocationKnown   bool
	Now                   time.Time
	GeoVelocity           float64
	IsNewDevice           bool
	IsNewLocation         bool
	IsImpossibleTravel    bool
	IsUserBaselineAnomaly bool
}

// Engine is the Policy Engine. It evaluates normalized access context and
// returns a deterministic decision without creating sessions, provisioning
// Gateways, signing certificates, or writing audit records.
type Engine struct {
	riskConfig config.RiskConfig
}

func NewEngine(riskConfigs ...config.RiskConfig) *Engine {
	cfg := &config.Config{}
	if len(riskConfigs) > 0 {
		cfg.Risk = riskConfigs[0]
	}
	cfg.ApplyDefaults()
	return &Engine{riskConfig: cfg.Risk}
}

// Evaluate processes a normalized access context against enabled policy rules.
// Rules are evaluated in deterministic policy-layer order by PA/store before
// they reach PE.
func (e *Engine) Evaluate(ctx AccessContext) *models.AccessDecision {
	req := ctx.Request
	now := ctx.Now
	if now.IsZero() {
		now = time.Now()
	}

	log.Printf("[PE] Evaluating access: user=%s resource=%s:%d protocol=%s",
		req.Username, req.Resource, req.ResourcePort, req.Protocol)

	riskCtx := models.RiskContext{
		UserID:                req.UserID,
		SourceIP:              req.SourceIP,
		DeviceHealth:          req.DeviceHealth,
		FailedAttempts:        ctx.FailedAttempts,
		IsNewDevice:           ctx.IsNewDevice,
		IsNewLocation:         ctx.IsNewLocation,
		TimeOfDay:             now,
		Protocol:              req.Protocol,
		GeoVelocity:           ctx.GeoVelocity,
		IsImpossibleTravel:    ctx.IsImpossibleTravel,
		IsUserBaselineAnomaly: ctx.IsUserBaselineAnomaly,
		AnomalyAlerts:         req.AnomalyAlerts,
		AnomalyScore:          req.AnomalyScore,
	}
	riskScore := perisk.CalculateRiskScore(riskCtx, e.riskConfig)
	observedAccess := accessConditionsFromContext(ctx)

	matchedRules := make([]*models.PolicyRule, 0)
	stepUpRules := make([]*models.PolicyRule, 0)
	var allowRule *models.PolicyRule
	var sessionControls models.SessionPolicyControls

	for _, rule := range ctx.Rules {
		if rule == nil || !rule.Enabled {
			continue
		}

		if !e.matchesRuleScope(rule, ctx, now, riskScore, observedAccess) {
			continue
		}

		matchedRules = append(matchedRules, rule)
		sessionControls = mergeSessionControls(sessionControls, rule.Conditions.Session)

		if !matchesHealthRequirements(rule.Conditions, req.DeviceHealth) {
			log.Printf("[PE] Rule matched but device health failed: %s (%s)", rule.Name, rule.ID)
			return &models.AccessDecision{
				Decision:         models.DecisionDeny,
				Reason:           fmt.Sprintf("Device health requirements failed by policy: %s", rule.Name),
				RiskScore:        riskScore,
				AccessConditions: observedAccess,
				SessionControls:  sessionControls,
				MatchedRule:      rule.ID,
			}
		}

		action := effectivePolicyAction(rule, ctx)
		log.Printf("[PE] Rule matched: %s (%s) -> action=%s", rule.Name, rule.ID, action)

		switch action {
		case models.DecisionDeny:
			return &models.AccessDecision{
				Decision:         models.DecisionDeny,
				Reason:           fmt.Sprintf("Blocked by policy: %s", rule.Name),
				RiskScore:        riskScore,
				AccessConditions: observedAccess,
				SessionControls:  sessionControls,
				MatchedRule:      rule.ID,
			}
		case models.DecisionStepUpRequired:
			stepUpRules = append(stepUpRules, rule)
		case models.DecisionAllow:
			if allowRule == nil {
				allowRule = rule
			}
		}
	}

	if len(matchedRules) == 0 {
		return e.defaultDecision(req, riskScore, observedAccess)
	}

	if len(stepUpRules) > 0 {
		requirement := combinedStepUpRequirementFromRules(stepUpRules, req.Resource)
		decision := &models.AccessDecision{
			Decision:         models.DecisionStepUpRequired,
			Reason:           fmt.Sprintf("Step-up verification required by %d matching policy rule(s)", len(stepUpRules)),
			RiskScore:        riskScore,
			AccessConditions: observedAccess,
			SessionControls:  sessionControls,
			MatchedRule:      requirement.PolicyID,
		}
		if stepUpSatisfied(ctx.Auth, requirement, now) {
			decision.Decision = models.DecisionAllow
			decision.Reason = fmt.Sprintf("Step-up verification already satisfies %d matching policy rule(s)", len(stepUpRules))
			decision.Policies = []string{req.Resource}
			decision.StepUp = &models.StepUpRequirement{
				AlreadySatisfied:  true,
				Methods:           append([]string(nil), requirement.Methods...),
				RequiredACR:       requirement.RequiredACR,
				MinStrength:       requirement.MinStrength,
				MaxAgeSeconds:     requirement.MaxAgeSeconds,
				CompletedMethod:   ctx.Auth.StepUpMethod,
				CompletedStrength: effectiveStepUpStrength(ctx.Auth),
			}
			if !ctx.Auth.StepUpVerifiedAt.IsZero() {
				decision.StepUp.CompletedAtUnix = ctx.Auth.StepUpVerifiedAt.UTC().Unix()
			}
		} else {
			decision.StepUp = requirement
		}
		return decision
	}

	if allowRule != nil {
		return &models.AccessDecision{
			Decision:         models.DecisionAllow,
			Reason:           fmt.Sprintf("Allowed by %d matching policy rule(s)", len(matchedRules)),
			RiskScore:        riskScore,
			AccessConditions: observedAccess,
			SessionControls:  sessionControls,
			MatchedRule:      allowRule.ID,
			Policies:         []string{req.Resource},
		}
	}

	return e.defaultDecision(req, riskScore, observedAccess)
}
