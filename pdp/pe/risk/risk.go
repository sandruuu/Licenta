package risk

import (
	"log"
	"time"

	"pdp/models"
)

// CalculateRiskScore computes a dynamic risk score (0-100) from normalized
// context supplied by PA. Higher scores represent higher risk.
func CalculateRiskScore(ctx models.RiskContext) int {
	score := 0

	if ctx.DeviceHealth != nil {
		if !ctx.DeviceHealth.ReportedAt.IsZero() {
			age := time.Since(ctx.DeviceHealth.ReportedAt)
			switch {
			case age > 30*time.Minute:
				log.Printf("[RISK] Posture critically stale: device=%s age=%s", ctx.DeviceHealth.DeviceID, age)
				score += 30
			case age > 10*time.Minute:
				log.Printf("[RISK] Posture stale: device=%s age=%s", ctx.DeviceHealth.DeviceID, age)
				score += 15
			}
		}

		healthScore := ctx.DeviceHealth.OverallScore
		switch {
		case healthScore >= 80:
			score += 0
		case healthScore >= 60:
			score += 10
		case healthScore >= 40:
			score += 20
		default:
			score += 35
		}

		for _, check := range ctx.DeviceHealth.Checks {
			if check.Status == "critical" {
				switch check.Name {
				case "Firewall":
					score += 5
				case "Antivirus":
					score += 5
				case "Disk Encryption":
					score += 3
				case "Password & Lock":
					score += 2
				}
			}
		}
	} else {
		score += 25
	}

	switch {
	case ctx.FailedAttempts >= 5:
		score += 20
	case ctx.FailedAttempts >= 3:
		score += 10
	case ctx.FailedAttempts >= 1:
		score += 5
	}

	hour := ctx.TimeOfDay.Hour()
	weekday := ctx.TimeOfDay.Weekday()
	isBusinessHours := weekday >= time.Monday && weekday <= time.Friday && hour >= 8 && hour < 18
	if !isBusinessHours {
		score += 10
		if hour >= 0 && hour < 6 {
			score += 5
		}
	}

	if ctx.IsNewDevice {
		score += 10
	}
	if ctx.IsNewLocation {
		score += 5
	}

	switch ctx.Protocol {
	case "rdp":
		score += 10
	case "ssh":
		score += 5
	case "https", "http":
		score += 0
	default:
		score += 5
	}

	if ctx.IsImpossibleTravel {
		score += 30
	} else if ctx.GeoVelocity > 500 {
		score += 15
	}

	if ctx.AnomalyScore > 0 {
		anomalyPoints := ctx.AnomalyScore
		if anomalyPoints > 25 {
			anomalyPoints = 25
		}
		score += anomalyPoints
		log.Printf("[RISK] Anomaly factor: +%d points (alerts=%v)", anomalyPoints, ctx.AnomalyAlerts)
	}

	if score > 100 {
		score = 100
	}

	log.Printf("[RISK] Score calculated: %d (device_health=%v, failed_attempts=%d, business_hours=%v, protocol=%s, geo_velocity=%.0f km/h, impossible=%v, anomaly_alerts=%d)",
		score, ctx.DeviceHealth != nil, ctx.FailedAttempts, isBusinessHours, ctx.Protocol, ctx.GeoVelocity, ctx.IsImpossibleTravel, len(ctx.AnomalyAlerts))

	return score
}
