package policy

import (
	"log"
	"time"

	"cloud/models"
)

// CalculateRiskScore computes a dynamic risk score (0-100) based on contextual factors.
// Higher score = higher risk.
//
// Risk factors considered:
//   - Device health posture
//   - Failed login attempts
//   - Time of access (outside business hours = higher risk)
//   - Source IP trust level
//   - Protocol sensitivity
//
// This implements contextual risk assessment as described in
// Zero Trust Architecture (NIST SP 800-207) and conditional access models.
func CalculateRiskScore(ctx models.RiskContext) int {
	score := 0

	// ─────────────────────────────────────────────
	// Factor 1: Device Health (0-35 points)
	// ─────────────────────────────────────────────
	if ctx.DeviceHealth != nil {
		healthScore := ctx.DeviceHealth.OverallScore
		switch {
		case healthScore >= 80:
			score += 0 // healthy device, no risk
		case healthScore >= 60:
			score += 10
		case healthScore >= 40:
			score += 20
		default:
			score += 35 // unhealthy device = high risk
		}

		// Additional risk for critical checks
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
		// No device health data = unknown posture = elevated risk
		score += 25
	}

	// ─────────────────────────────────────────────
	// Factor 2: Failed Login Attempts (0-20 points)
	// ─────────────────────────────────────────────
	switch {
	case ctx.FailedAttempts >= 5:
		score += 20
	case ctx.FailedAttempts >= 3:
		score += 10
	case ctx.FailedAttempts >= 1:
		score += 5
	}

	// ─────────────────────────────────────────────
	// Factor 3: Time of Access (0-15 points)
	// Outside business hours (M-F 08:00-18:00) = higher risk
	// ─────────────────────────────────────────────
	hour := ctx.TimeOfDay.Hour()
	weekday := ctx.TimeOfDay.Weekday()

	isBusinessHours := weekday >= time.Monday && weekday <= time.Friday &&
		hour >= 8 && hour < 18

	if !isBusinessHours {
		score += 10
		if hour >= 0 && hour < 6 {
			score += 5 // late night = even higher risk
		}
	}

	// ─────────────────────────────────────────────
	// Factor 4: New Device or Location (0-15 points)
	// ─────────────────────────────────────────────
	if ctx.IsNewDevice {
		score += 10
	}
	if ctx.IsNewLocation {
		score += 5
	}

	// ─────────────────────────────────────────────
	// Factor 5: Protocol Sensitivity (0-15 points)
	// ─────────────────────────────────────────────
	switch ctx.Protocol {
	case "rdp":
		score += 10 // RDP is frequently targeted
	case "ssh":
		score += 5
	case "https", "http":
		score += 0
	default:
		score += 5
	}

	// ─────────────────────────────────────────────
	// Factor 6: Geo-Velocity / Impossible Travel (0-30 points)
	// Detects physically impossible location changes between logins.
	// ─────────────────────────────────────────────
	if ctx.IsImpossibleTravel {
		score += 30
	} else if ctx.GeoVelocity > 500 {
		score += 15 // suspicious speed (500–900 km/h)
	}

	// ─────────────────────────────────────────────
	// Factor 7: Gateway Anomaly Detection (0-25 points)
	// Uses behavioral signals from the gateway PEP anomaly detector.
	// ─────────────────────────────────────────────
	if ctx.AnomalyScore > 0 {
		anomalyPoints := ctx.AnomalyScore
		if anomalyPoints > 25 {
			anomalyPoints = 25
		}
		score += anomalyPoints
		log.Printf("[RISK] Anomaly factor: +%d points (alerts=%v)", anomalyPoints, ctx.AnomalyAlerts)
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	log.Printf("[RISK] Score calculated: %d (device_health=%v, failed_attempts=%d, business_hours=%v, protocol=%s, geo_velocity=%.0f km/h, impossible=%v, anomaly_alerts=%d)",
		score, ctx.DeviceHealth != nil, ctx.FailedAttempts, isBusinessHours, ctx.Protocol, ctx.GeoVelocity, ctx.IsImpossibleTravel, len(ctx.AnomalyAlerts))

	return score
}
