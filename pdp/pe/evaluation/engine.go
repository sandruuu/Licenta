package evaluation

import (
	"fmt"
	"log"
	"time"

	"pdp/models"
)

// AccessContext is evaluated by PE.
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

// Engine is the Policy Engine.
type Engine struct{}

func NewEngine() *Engine {
	return &Engine{}
}

// Evaluate applies enabled policy rules.
func (e *Engine) Evaluate(ctx AccessContext) *models.AccessDecision {
	req := ctx.Request
	now := ctx.Now
	if now.IsZero() {
		now = time.Now()
	}

	log.Printf("[PE] Evaluating access: user=%s resource=%s:%d protocol=%s",
		req.Username, req.Resource, req.ResourcePort, req.Protocol)

	observedAccess := accessConditionsFromContext(ctx)
	riskSignals := riskSignalsFromContext(ctx, observedAccess, req)

	matchedRules := make([]*models.PolicyRule, 0)
	stepUpRules := make([]*models.PolicyRule, 0)
	var allowRule *models.PolicyRule
	var sessionControls models.SessionPolicyControls
	activeLayer := 0

	for _, rule := range ctx.Rules {
		if rule == nil || !rule.Enabled {
			continue
		}

		if !e.matchesRuleScope(rule, ctx, now, observedAccess) {
			continue
		}

		layer := policyLayerPriority(rule)
		if activeLayer != 0 && layer != activeLayer {
			break
		}
		activeLayer = layer
		matchedRules = append(matchedRules, rule)
		sessionControls = mergeSessionControls(sessionControls, rule.Conditions.Session)

		if !matchesHealthRequirements(rule.Conditions, req.DeviceHealth) {
			log.Printf("[PE] Rule matched but device health failed: %s (%s)", rule.Name, rule.ID)
			return &models.AccessDecision{
				Decision:         models.DecisionDeny,
				Reason:           fmt.Sprintf("Device health requirements failed by policy: %s", rule.Name),
				RiskSignals:      riskSignals,
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
				RiskSignals:      riskSignals,
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
		return e.defaultDecision(req, observedAccess, riskSignals)
	}

	if len(stepUpRules) > 0 {
		requirement := combinedStepUpRequirementFromRules(stepUpRules, req.Resource)
		decision := &models.AccessDecision{
			Decision:         models.DecisionStepUpRequired,
			Reason:           fmt.Sprintf("Step-up verification required by %d matching policy rule(s)", len(stepUpRules)),
			RiskSignals:      riskSignals,
			AccessConditions: observedAccess,
			SessionControls:  sessionControls,
			MatchedRule:      requirement.PolicyID,
		}
		if stepUpSatisfied(ctx.Auth, requirement, now) && stepUpContextMatches(ctx.Auth, req, riskSignals) {
			decision.Decision = models.DecisionAllow
			decision.Reason = fmt.Sprintf("Step-up verification already satisfies %d matching policy rule(s)", len(stepUpRules))
			decision.Policies = []string{req.Resource}
			decision.StepUp = &models.StepUpRequirement{
				AlreadySatisfied:    true,
				Methods:             append([]string(nil), requirement.Methods...),
				RequiredACR:         requirement.RequiredACR,
				MinStrength:         requirement.MinStrength,
				MaxAgeSeconds:       requirement.MaxAgeSeconds,
				CompletedMethod:     ctx.Auth.StepUpMethod,
				CompletedStrength:   effectiveStepUpStrength(ctx.Auth),
				CompletedAAGUID:     ctx.Auth.StepUpAAGUID,
				CompletedAttachment: ctx.Auth.StepUpAttachment,
			}
			if !ctx.Auth.StepUpVerifiedAt.IsZero() {
				decision.StepUp.CompletedAtUnix = ctx.Auth.StepUpVerifiedAt.UTC().Unix()
			}
			if !ctx.Auth.StepUpExpiresAt.IsZero() {
				decision.StepUp.ExpiresAt = ctx.Auth.StepUpExpiresAt.UTC()
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
			RiskSignals:      riskSignals,
			AccessConditions: observedAccess,
			SessionControls:  sessionControls,
			MatchedRule:      allowRule.ID,
			Policies:         []string{req.Resource},
		}
	}

	return e.defaultDecision(req, observedAccess, riskSignals)
}
