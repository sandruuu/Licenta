package evaluation

import (
	"log"
	"strings"
	"time"

	"pdp/models"
)

func (e *Engine) matchesRuleScope(rule *models.PolicyRule, ctx AccessContext, now time.Time, observedAccess models.AccessConditions) bool {
	req := ctx.Request
	cond := rule.Conditions

	if !matchesAccessConditions(cond.AccessConditions, observedAccess, cond.AccessMatchMode) {
		return false
	}

	if !matchesRiskConditions(cond.Risk, observedAccess, ctx, req) {
		return false
	}

	if len(cond.AllowedRoles) > 0 {
		if strings.TrimSpace(ctx.UserRole) == "" || !containsString(cond.AllowedRoles, ctx.UserRole) {
			return false
		}
	}

	if len(cond.AllowedUsers) > 0 {
		if !containsAnyString(cond.AllowedUsers, req.UserID, req.Username, ctx.UserEmail, ctx.DirectoryUserID, ctx.DirectoryUserName) {
			return false
		}
	}

	if len(cond.AllowedGroups) > 0 {
		if !intersectsString(cond.AllowedGroups, append(ctx.DirectoryGroupIDs, ctx.DirectoryGroupNames...)) {
			return false
		}
	}

	loc := time.UTC
	if cond.Timezone != "" {
		if tz, err := time.LoadLocation(cond.Timezone); err == nil {
			loc = tz
		} else {
			log.Printf("[PE] Invalid timezone %q, falling back to UTC", cond.Timezone)
		}
	}
	ruleNow := now.In(loc)

	if cond.DateRangeStart != "" {
		if start, err := time.Parse("2006-01-02", cond.DateRangeStart); err == nil {
			if ruleNow.Before(start) {
				return false
			}
		}
	}
	if cond.DateRangeEnd != "" {
		if end, err := time.Parse("2006-01-02", cond.DateRangeEnd); err == nil {
			if ruleNow.After(end.Add(24 * time.Hour)) {
				return false
			}
		}
	}

	if len(cond.BlockedDates) > 0 {
		todayStr := ruleNow.Format("2006-01-02")
		for _, blocked := range cond.BlockedDates {
			if blocked == todayStr {
				return false
			}
		}
	}

	if cond.AllowedTimeStart != "" && cond.AllowedTimeEnd != "" {
		if !isWithinTimeWindowTZ(cond.AllowedTimeStart, cond.AllowedTimeEnd, ruleNow) {
			return false
		}
	}

	if len(cond.AllowedDays) > 0 {
		today := ruleNow.Weekday().String()
		if !containsString(cond.AllowedDays, today) {
			return false
		}
	}

	if len(cond.TargetResources) > 0 {
		if !containsString(cond.TargetResources, req.Resource) && !containsString(cond.TargetResources, req.AppID) {
			return false
		}
	}

	if len(cond.TargetPorts) > 0 {
		if !containsInt(cond.TargetPorts, req.ResourcePort) {
			return false
		}
	}

	if !matchesProcessConditions(cond, rule.Action, req.Process) {
		return false
	}

	return true
}

func (e *Engine) defaultDecision(req models.AccessRequest, observedAccess models.AccessConditions, riskSignals []string) *models.AccessDecision {
	log.Printf("[PE] Default decision: DENY (no matching rule)")
	return &models.AccessDecision{
		Decision:         models.DecisionDeny,
		Reason:           "No matching access rule - denied by zero-trust default",
		RiskSignals:      append([]string(nil), riskSignals...),
		AccessConditions: observedAccess,
	}
}
