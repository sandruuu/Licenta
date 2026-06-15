package evaluation

import (
	"strings"

	"pdp/models"
)

func accessConditionsFromContext(ctx AccessContext) models.AccessConditions {
	req := ctx.Request
	return models.AccessConditions{
		Location: models.LocationAccessConditions{
			NewLocation:         ctx.IsNewLocation,
			ImpossibleTravel:    ctx.IsImpossibleTravel,
			UserBaselineAnomaly: ctx.IsUserBaselineAnomaly,
		},
		Connection: models.ConnectionAccessConditions{
			SensitiveProtocol: sensitiveProtocol(req),
		},
	}
}

func matchesAccessConditions(required, observed models.AccessConditions, mode string) bool {
	if required.Empty() {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(mode), "any") {
		return (required.Location.NewLocation && observed.Location.NewLocation) ||
			(required.Location.ImpossibleTravel && observed.Location.ImpossibleTravel) ||
			(required.Location.UserBaselineAnomaly && observed.Location.UserBaselineAnomaly) ||
			(required.Connection.SensitiveProtocol && observed.Connection.SensitiveProtocol)
	}
	if required.Location.NewLocation && !observed.Location.NewLocation {
		return false
	}
	if required.Location.ImpossibleTravel && !observed.Location.ImpossibleTravel {
		return false
	}
	if required.Location.UserBaselineAnomaly && !observed.Location.UserBaselineAnomaly {
		return false
	}
	if required.Connection.SensitiveProtocol && !observed.Connection.SensitiveProtocol {
		return false
	}
	return true
}

func matchesRiskConditions(required models.RiskPolicyConditions, riskScore int, observedAccess models.AccessConditions, ctx AccessContext, req models.AccessRequest) bool {
	if required.MinScore > 0 && riskScore < required.MinScore {
		return false
	}
	if required.MaxScore > 0 && riskScore > required.MaxScore {
		return false
	}
	if len(required.Levels) > 0 && !containsString(required.Levels, riskLevel(riskScore)) {
		return false
	}
	for _, signal := range required.Signals {
		if !riskSignalObserved(signal, observedAccess, ctx, req) {
			return false
		}
	}
	return true
}

func riskLevel(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 30:
		return "medium"
	default:
		return "low"
	}
}

func riskSignalObserved(signal string, observedAccess models.AccessConditions, ctx AccessContext, req models.AccessRequest) bool {
	switch normalizeHealthToken(signal) {
	case "new_location":
		return observedAccess.Location.NewLocation
	case "impossible_travel":
		return observedAccess.Location.ImpossibleTravel
	case "unrealistic_travel":
		return observedAccess.Location.ImpossibleTravel
	case "user_baseline_anomaly", "baseline_anomaly", "user_baseline":
		return ctx.IsUserBaselineAnomaly
	case "new_device":
		return ctx.IsNewDevice
	case "device_non_compliant", "non_compliant_device", "not_compliant_device":
		return deviceNonCompliant(req.DeviceHealth)
	case "compromised_endpoint":
		return compromisedEndpoint(req.DeviceHealth)
	case "sensitive_protocol":
		return observedAccess.Connection.SensitiveProtocol
	case "failed_attempts":
		return ctx.FailedAttempts > 0
	case "anomaly", "anomaly_alert":
		return req.AnomalyScore > 0 || len(req.AnomalyAlerts) > 0
	case "anonymous_network", "anonymous", "tor", "vpn", "proxy":
		return anomalyAlertObserved(req.AnomalyAlerts, signal)
	default:
		return anomalyAlertObserved(req.AnomalyAlerts, signal)
	}
}

func anomalyAlertObserved(alerts []string, signal string) bool {
	normalizedSignal := normalizeHealthToken(signal)
	for _, alert := range alerts {
		if normalizeHealthToken(alert) == normalizedSignal {
			return true
		}
	}
	return false
}

func sensitiveProtocol(req models.AccessRequest) bool {
	switch strings.ToLower(strings.TrimSpace(req.Protocol)) {
	case "ssh", "rdp":
		return true
	}
	return req.ResourcePort == 22 || req.ResourcePort == 3389
}

func deviceNonCompliant(report *models.DeviceHealthReport) bool {
	if report == nil {
		return false
	}
	for _, check := range report.Checks {
		if healthCheckStatusIn(check.Status, []string{"critical", "fail", "failed", "error", "unhealthy", "non_compliant", "non-compliant", "not_compliant", "compromised"}) {
			return true
		}
	}
	return false
}

func compromisedEndpoint(report *models.DeviceHealthReport) bool {
	if report == nil {
		return false
	}
	if endpointHasStatus(report, []string{"compromised", "secure_endpoint", "endpoint_protection", "edr", "xdr"}, []string{"critical", "fail", "failed", "compromised"}) {
		return true
	}
	for _, check := range report.Checks {
		if healthCheckStatusIn(check.Status, []string{"compromised"}) {
			return true
		}
	}
	return false
}
