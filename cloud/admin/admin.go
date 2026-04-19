package admin

import (
	"log"
	"strconv"

	"cloud/config"
	"cloud/idp"
	"cloud/models"
	"cloud/policy"
	"cloud/store"
)

// PolicyAdministrator (PA) is the central coordinator that ties together
// the Identity Provider (IdP), Policy Engine (PE), session management,
// and audit logging. It serves as the decision-making authority in the
// Zero Trust architecture.
//
// In the Cisco Duo analogy, the PA + PE + IdP together form the "Duo Cloud".
type PolicyAdministrator struct {
	IdP      *idp.IdentityProvider
	Engine   *policy.Engine
	Rules    *policy.RuleManager
	Sessions *SessionManager
	Audit    *AuditLogger
	Store    *store.Store
	Cfg      *config.Config
}

// NewPolicyAdministrator creates and initializes the Policy Administrator
func NewPolicyAdministrator(cfg *config.Config, s *store.Store) *PolicyAdministrator {
	pa := &PolicyAdministrator{
		IdP:      idp.New(cfg, s),
		Engine:   policy.NewEngine(s),
		Rules:    policy.NewRuleManager(s),
		Sessions: NewSessionManager(s, cfg.SessionExpiry, cfg.MaxSessions),
		Audit:    NewAuditLogger(s),
		Store:    s,
		Cfg:      cfg,
	}

	// Initialize default policy rules
	policy.InitDefaultRules(s)

	return pa
}

// AuthorizeAccess is the main entry point called by the gateway (PEP).
// It performs the complete authorization flow:
// 1. Validates the JWT auth token
// 2. Evaluates policy rules against the access request
// 3. Creates a session if access is granted
// 4. Logs the decision in the audit trail
func (pa *PolicyAdministrator) AuthorizeAccess(req models.AccessRequest) *models.AccessDecision {
	// Step 1: Validate the authentication token
	claims, err := pa.IdP.ValidateToken(req.AuthToken)
	if err != nil {
		pa.Audit.LogEvent("access_request", req.UserID, req.Username, req.SourceIP,
			req.Resource, "deny", "Invalid auth token: "+err.Error(), false)
		return &models.AccessDecision{
			Decision: "deny",
			Reason:   "Invalid or expired authentication token",
		}
	}

	// Enrich the request with validated user info
	req.UserID = claims.UserID
	req.Username = claims.Username

	// Load device health data if available
	if req.DeviceHealth == nil && req.DeviceID != "" {
		if health, ok := pa.Store.GetDeviceHealth(req.DeviceID); ok {
			req.DeviceHealth = health
		}
	}

	// Explicit health gate: deny access if no health data is available for the device
	if req.DeviceHealth == nil && req.DeviceID != "" {
		pa.Audit.LogEvent("access_request", req.UserID, req.Username, req.SourceIP,
			req.Resource, "deny", "Device health data unavailable", false)
		return &models.AccessDecision{
			Decision: "deny",
			Reason:   "Device health data unavailable — ensure device-health-app is running and enrolled",
		}
	}

	// Step 2: Evaluate policy rules
	decision := pa.Engine.Evaluate(req)

	// Step 3: If access is allowed, create a session
	if decision.Decision == "allow" {
		session, err := pa.Sessions.CreateSession(decision, req)
		if err != nil {
			log.Printf("[PA] Failed to create session: %v", err)
		} else {
			decision.SessionID = session.ID
			decision.ExpiresAt = session.ExpiresAt.Unix()
		}
	}

	// Step 4: Audit the decision
	pa.Audit.LogEvent("access_request", req.UserID, req.Username, req.SourceIP,
		req.Resource, decision.Decision,
		decision.Reason, decision.Decision == "allow")

	// Step 5: Record login location for geo-velocity tracking
	if req.SourceIP != "" && req.UserID != "" && pa.Engine.Geo != nil {
		go pa.Engine.Geo.SaveCurrentLocation(req.UserID, req.SourceIP)
	}

	log.Printf("[PA] Access decision for %s → %s: %s (risk=%d)",
		req.Username, req.Resource, decision.Decision, decision.RiskScore)

	return decision
}

// ReportDeviceHealth processes a device health report from the gateway
func (pa *PolicyAdministrator) ReportDeviceHealth(report *models.DeviceHealthReport) {
	pa.Store.SaveDeviceHealth(report)
	pa.Audit.LogEvent("device_health_report", "", "", "", report.DeviceID,
		"", "Device health reported: score="+strconv.Itoa(report.OverallScore), true)
	log.Printf("[PA] Device health report received: device=%s score=%d",
		report.DeviceID, report.OverallScore)
}
