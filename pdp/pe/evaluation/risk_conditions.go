package evaluation

import (
	"strings"

	"pdp/models"
)

func accessConditionsFromContext(ctx AccessContext) models.AccessConditions {
	return models.AccessConditions{
		Location: models.LocationAccessConditions{
			NewLocation:         ctx.IsNewLocation,
			ImpossibleTravel:    ctx.IsImpossibleTravel,
			UserBaselineAnomaly: ctx.IsUserBaselineAnomaly,
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
			(required.Location.UserBaselineAnomaly && observed.Location.UserBaselineAnomaly)
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
	return true
}

func matchesRiskConditions(required models.RiskPolicyConditions, observedAccess models.AccessConditions, ctx AccessContext, req models.AccessRequest) bool {
	for _, signal := range required.Signals {
		if !riskSignalObserved(signal, observedAccess, ctx, req) {
			return false
		}
	}
	return true
}

func riskSignalsFromContext(ctx AccessContext, observedAccess models.AccessConditions, req models.AccessRequest) []string {
	signals := make([]string, 0, 10)
	add := func(signal string) {
		signal = normalizeHealthToken(signal)
		if signal == "" || containsString(signals, signal) {
			return
		}
		signals = append(signals, signal)
	}
	if observedAccess.Location.NewLocation {
		add("new_location")
	}
	if observedAccess.Location.ImpossibleTravel {
		add("impossible_travel")
	}
	if observedAccess.Location.UserBaselineAnomaly {
		add("user_baseline_anomaly")
	}
	if ctx.IsNewDevice {
		add("new_device")
	}
	if deviceNonCompliant(req.DeviceHealth) {
		add("device_non_compliant")
	}
	if compromisedEndpoint(req.DeviceHealth) {
		add("compromised_endpoint")
	}
	if ctx.FailedAttempts > 0 {
		add("failed_attempts")
	}
	if len(req.AnomalyAlerts) > 0 {
		add("anomaly")
	}
	for _, alert := range req.AnomalyAlerts {
		add(alert)
	}
	return signals
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
	case "failed_attempts":
		return ctx.FailedAttempts > 0
	case "anomaly", "anomaly_alert":
		return len(req.AnomalyAlerts) > 0
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
