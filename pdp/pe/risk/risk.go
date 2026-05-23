package risk

import (
	"log"
	"strings"
	"time"

	"pdp/config"
	"pdp/models"
)

// CalculateRiskScore computes a dynamic risk score (0-100) from normalized
// context supplied by PA. Higher scores represent higher risk.
func CalculateRiskScore(ctx models.RiskContext, cfgs ...config.RiskConfig) int {
	cfg := normalizedRiskConfig(cfgs...)
	score := 0

	if ctx.DeviceHealth != nil {
		if !ctx.DeviceHealth.ReportedAt.IsZero() {
			age := time.Since(ctx.DeviceHealth.ReportedAt)
			switch {
			case age > cfg.DeviceDataCriticalAfter:
				log.Printf("[RISK] Device data critically stale: device=%s age=%s", ctx.DeviceHealth.DeviceID, age)
				score += cfg.DeviceDataCriticalPoints
			case age > cfg.DeviceDataStaleAfter:
				log.Printf("[RISK] Device data stale: device=%s age=%s", ctx.DeviceHealth.DeviceID, age)
				score += cfg.DeviceDataStalePoints
			}
		}

		healthScore := ctx.DeviceHealth.OverallScore
		switch {
		case healthScore >= cfg.HealthExcellentMin:
			score += 0
		case healthScore >= cfg.HealthGoodMin:
			score += cfg.HealthGoodPoints
		case healthScore >= cfg.HealthFairMin:
			score += cfg.HealthFairPoints
		default:
			score += cfg.HealthPoorPoints
		}

		for _, check := range ctx.DeviceHealth.Checks {
			if check.Status == "critical" {
				if points, ok := cfg.CriticalCheckPoints[check.Name]; ok {
					score += points
				}
			}
		}
	} else {
		score += cfg.NoDeviceHealthPoints
	}

	switch {
	case ctx.FailedAttempts >= cfg.FailedAttemptsHigh:
		score += cfg.FailedAttemptsHighPoints
	case ctx.FailedAttempts >= cfg.FailedAttemptsMedium:
		score += cfg.FailedAttemptsMediumPoints
	case ctx.FailedAttempts >= cfg.FailedAttemptsLow:
		score += cfg.FailedAttemptsLowPoints
	}

	hour := ctx.TimeOfDay.Hour()
	isBusinessHours := isConfiguredBusinessDay(ctx.TimeOfDay.Weekday(), cfg.BusinessDays) &&
		hour >= cfg.BusinessHoursStart && hour < cfg.BusinessHoursEnd
	if !isBusinessHours {
		score += cfg.OutsideBusinessPoints
		if hour >= cfg.NightHoursStart && hour < cfg.NightHoursEnd {
			score += cfg.NightHoursPoints
		}
	}

	if ctx.IsNewDevice {
		score += cfg.NewDevicePoints
	}
	if ctx.IsNewLocation {
		score += cfg.NewLocationPoints
	}

	protocol := strings.ToLower(strings.TrimSpace(ctx.Protocol))
	if points, ok := cfg.ProtocolPoints[protocol]; ok {
		score += points
	} else {
		score += cfg.UnknownProtocolPoints
	}

	if ctx.IsImpossibleTravel {
		score += cfg.ImpossibleTravelPoints
	} else if ctx.GeoVelocity > cfg.SuspiciousGeoVelocityKMH {
		score += cfg.SuspiciousGeoVelocityPoints
	}

	if ctx.AnomalyScore > 0 {
		anomalyPoints := ctx.AnomalyScore
		if anomalyPoints > cfg.MaxAnomalyPoints {
			anomalyPoints = cfg.MaxAnomalyPoints
		}
		score += anomalyPoints
		log.Printf("[RISK] Anomaly factor: +%d points (alerts=%v)", anomalyPoints, ctx.AnomalyAlerts)
	}

	if score > cfg.MaxScore {
		score = cfg.MaxScore
	}

	log.Printf("[RISK] Score calculated: %d (device_health=%v, failed_attempts=%d, business_hours=%v, protocol=%s, geo_velocity=%.0f km/h, impossible=%v, anomaly_alerts=%d)",
		score, ctx.DeviceHealth != nil, ctx.FailedAttempts, isBusinessHours, ctx.Protocol, ctx.GeoVelocity, ctx.IsImpossibleTravel, len(ctx.AnomalyAlerts))

	return score
}

func normalizedRiskConfig(cfgs ...config.RiskConfig) config.RiskConfig {
	cfg := &config.Config{}
	if len(cfgs) > 0 {
		cfg.Risk = cfgs[0]
	}
	cfg.ApplyDefaults()
	return cfg.Risk
}

func isConfiguredBusinessDay(weekday time.Weekday, days []string) bool {
	if len(days) == 0 {
		return false
	}
	name := weekday.String()
	for _, day := range days {
		if strings.EqualFold(strings.TrimSpace(day), name) {
			return true
		}
	}
	return false
}
