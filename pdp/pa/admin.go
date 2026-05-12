package pa

import (
	"pdp/config"
	"pdp/models"
	"pdp/pa/audit"
	"pdp/pa/auth"
	"pdp/pa/catalog"
	"pdp/pa/devices"
	"pdp/pa/enrollment"
	"pdp/pa/gateway"
	"pdp/pa/policies"
	"pdp/pa/resources"
	"pdp/pa/sessions"
	"pdp/pe/evaluation"
	"pdp/store"
)

// PolicyAdministrator (PA) is the central coordinator that ties together
// authentication, Policy Engine (PE), session management, Gateway control, and
// audit logging. It orchestrates workflows and delegates access decisions to PE
// through a normalized context.
type PolicyAdministrator struct {
	Auth       *auth.Service
	Engine     *evaluation.Engine
	Geo        *policies.GeoLocator
	Rules      *policies.RuleManager
	Catalog    *catalog.Service
	Devices    *devices.Service
	Enrollment *enrollment.Service
	Gateways   *gateway.Service
	Resources  *resources.Service
	Sessions   *sessions.SessionManager
	Audit      *audit.AuditLogger
	Store      *store.Store
	Cfg        *config.Config
}

// NewPolicyAdministrator creates and initializes the Policy Administrator
func NewPolicyAdministrator(cfg *config.Config, s *store.Store) *PolicyAdministrator {
	auditLogger := audit.NewAuditLogger(s)
	pa := &PolicyAdministrator{
		Auth:       auth.New(cfg, s),
		Engine:     evaluation.NewEngine(),
		Geo:        policies.NewGeoLocator(s),
		Rules:      policies.NewRuleManager(s),
		Catalog:    catalog.NewService(s),
		Devices:    devices.NewService(s, auditLogger),
		Enrollment: enrollment.NewService(s),
		Gateways:   gateway.NewService(s, cfg.PKIRoleGateway),
		Resources:  resources.NewService(s, cfg.PKIRoleResource),
		Sessions:   sessions.NewSessionManager(s, cfg.SessionExpiry, cfg.MaxSessions),
		Audit:      auditLogger,
		Store:      s,
		Cfg:        cfg,
	}

	// Initialize default policy rules
	policies.InitDefaultRules(s)

	return pa
}

// ReportDeviceHealth processes a scored device health report from direct device telemetry or legacy compatibility paths.
func (pa *PolicyAdministrator) ReportDeviceHealth(report *models.DeviceHealthReport) {
	if pa == nil || pa.Devices == nil {
		return
	}
	pa.Devices.RecordHealth(report)
}

func (pa *PolicyAdministrator) ReportDevicePosture(report *models.DevicePostureReport) {
	if pa == nil || pa.Devices == nil {
		return
	}
	pa.Devices.RecordPosture(report)
}
