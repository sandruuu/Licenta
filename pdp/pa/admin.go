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
	Catalog    *catalog.Service
	Devices    *devices.Service
	Enrollment *enrollment.Service
	Gateways   *gateway.Service
	Resources  *resources.Service
	Sessions   *sessions.SessionManager
	StepUps    *StepUpManager
	Audit      *audit.AuditLogger
	Store      *store.Store
	Cfg        *config.Config
}

// NewPolicyAdministrator creates and initializes the Policy Administrator
func NewPolicyAdministrator(cfg *config.Config, s *store.Store) *PolicyAdministrator {
	cfg.ApplyDefaults()
	auditLogger := audit.NewAuditLogger(s)
	pa := &PolicyAdministrator{
		Auth:    auth.New(cfg, s),
		Engine:  evaluation.NewEngine(cfg.Risk),
		Geo:     policies.NewGeoLocator(s, cfg.Geo),
		Catalog: catalog.NewService(s, cfg.Runtime.CatalogTTLSeconds),
		Devices: devices.NewService(s, auditLogger),
		Enrollment: enrollment.NewService(s, enrollment.Config{
			CertificateValidityDays: cfg.Enrollment.CertificateValidityDays,
			BrowserSessionTTL:       cfg.Enrollment.BrowserSessionTTL,
		}),
		Gateways: gateway.NewService(s, cfg.PKIRoleGateway, gateway.Config{
			CertificateValidityDays: cfg.Gateway.CertificateValidityDays,
			EnrollmentTokenTTL:      cfg.Gateway.EnrollmentTokenTTL,
		}),
		Resources: resources.NewService(s),
		Sessions:  sessions.NewSessionManager(s, cfg.SessionExpiry, cfg.MaxSessions),
		StepUps:   NewStepUpManager(),
		Audit:     auditLogger,
		Store:     s,
		Cfg:       cfg,
	}

	return pa
}

// ReportDeviceHealth processes a scored device health report from compatibility paths.
func (pa *PolicyAdministrator) ReportDeviceHealth(report *models.DeviceHealthReport) {
	if pa == nil || pa.Devices == nil {
		return
	}
	pa.Devices.RecordHealth(report)
}

func (pa *PolicyAdministrator) ReportDeviceData(report *models.DeviceDataReport) {
	if pa == nil || pa.Devices == nil {
		return
	}
	pa.Devices.RecordDeviceData(report)
}
