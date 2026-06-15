package evaluation

import (
	"path/filepath"
	"strings"

	"pdp/models"
)

func matchesProcessConditions(cond models.RuleConditions, action string, process *models.ProcessIdentity) bool {
	if cond.RequireProcessIdentity && process == nil {
		return false
	}
	if len(cond.AllowedProcessNames) == 0 && len(cond.BlockedProcessNames) == 0 &&
		len(cond.AllowedProcessHashes) == 0 && len(cond.BlockedProcessHashes) == 0 {
		return true
	}
	if process == nil {
		return false
	}

	blockedNameMatch := len(cond.BlockedProcessNames) > 0 && processNameMatches(cond.BlockedProcessNames, process)
	blockedHashMatch := len(cond.BlockedProcessHashes) > 0 && processHashMatches(cond.BlockedProcessHashes, process.SHA256)
	if strings.EqualFold(action, "deny") && (len(cond.BlockedProcessNames) > 0 || len(cond.BlockedProcessHashes) > 0) {
		if !blockedNameMatch && !blockedHashMatch {
			return false
		}
	} else if blockedNameMatch || blockedHashMatch {
		return false
	}
	if len(cond.AllowedProcessNames) > 0 && !processNameMatches(cond.AllowedProcessNames, process) {
		return false
	}
	if len(cond.AllowedProcessHashes) > 0 && !processHashMatches(cond.AllowedProcessHashes, process.SHA256) {
		return false
	}
	return true
}

func matchesHealthRequirements(cond models.RuleConditions, report *models.DeviceHealthReport) bool {
	requiredChecks := cond.DevicePosture.RequiredChecks
	requiredStatus := cond.DevicePosture.RequiredStatus
	if len(requiredChecks) == 0 {
		return true
	}
	if report == nil {
		return false
	}
	for _, reqCheck := range requiredChecks {
		found := false
		for _, check := range report.Checks {
			if strings.EqualFold(check.Name, reqCheck) {
				found = true
				if requiredStatus != "" && !strings.EqualFold(check.Status, requiredStatus) {
					return false
				}
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func endpointHasStatus(report *models.DeviceHealthReport, names, statuses []string) bool {
	if report == nil {
		return false
	}
	for _, check := range report.Checks {
		if healthCheckNameIn(check.Name, names) && healthCheckStatusIn(check.Status, statuses) {
			return true
		}
	}
	return false
}

func healthCheckNameIn(value string, names []string) bool {
	value = normalizeHealthToken(value)
	if value == "" {
		return false
	}
	for _, name := range names {
		if normalizeHealthToken(name) == value {
			return true
		}
	}
	return false
}

func healthCheckStatusIn(value string, statuses []string) bool {
	value = normalizeHealthToken(value)
	if value == "" {
		return false
	}
	for _, status := range statuses {
		if normalizeHealthToken(status) == value {
			return true
		}
	}
	return false
}

func normalizeHealthToken(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "_")
	value = strings.ReplaceAll(value, " ", "_")
	return value
}

func processNameMatches(allowed []string, process *models.ProcessIdentity) bool {
	if process == nil {
		return false
	}
	candidates := []string{process.Name, process.Path}
	if process.Path != "" {
		candidates = append(candidates, filepath.Base(process.Path))
	}
	for _, candidate := range candidates {
		if containsString(allowed, candidate) {
			return true
		}
	}
	return false
}

func processHashMatches(allowed []string, hash string) bool {
	if strings.TrimSpace(hash) == "" {
		return false
	}
	for _, candidate := range allowed {
		if strings.EqualFold(strings.TrimSpace(candidate), strings.TrimSpace(hash)) {
			return true
		}
	}
	return false
}
