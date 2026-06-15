package pa

import (
	"time"

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
	"pdp/runtime/redisstate"
	"pdp/store"
	"strings"
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
	Runtime    *redisstate.Client
	Cfg        *config.Config
}

// NewPolicyAdministrator creates and initializes the Policy Administrator
func NewPolicyAdministrator(cfg *config.Config, s *store.Store, runtimeState *redisstate.Client) *PolicyAdministrator {
	cfg.ApplyDefaults()
	auditLogger := audit.NewAuditLogger(s)
	pa := &PolicyAdministrator{
		Auth:    auth.New(cfg, s, runtimeState),
		Engine:  evaluation.NewEngine(cfg.Risk),
		Geo:     policies.NewGeoLocator(s, runtimeState, cfg.Geo),
		Catalog: catalog.NewService(s, cfg.Runtime.CatalogTTLSeconds),
		Devices: devices.NewService(s, auditLogger),
		Enrollment: enrollment.NewService(s, runtimeState, enrollment.Config{
			CertificateValidityDays: cfg.Enrollment.CertificateValidityDays,
			BrowserSessionTTL:       cfg.Enrollment.BrowserSessionTTL,
		}),
		Gateways: gateway.NewService(s, cfg.PKIRoleGateway, gateway.Config{
			CertificateValidityDays: cfg.Gateway.CertificateValidityDays,
			EnrollmentTokenTTL:      cfg.Gateway.EnrollmentTokenTTL,
		}),
		Resources: resources.NewService(s),
		Sessions:  sessions.NewSessionManager(s, cfg.SessionExpiry, cfg.MaxSessions),
		StepUps:   NewStepUpManager(runtimeState),
		Audit:     auditLogger,
		Store:     s,
		Runtime:   runtimeState,
		Cfg:       cfg,
	}

	pa.Enrollment.SetInteractiveSessionExpiredHandler(func(session enrollment.InteractiveSession, _ time.Time) {
		resource := strings.TrimSpace(session.Hostname)
		if resource == "" {
			resource = strings.TrimSpace(session.ID)
		}
		details := "Device enrollment expired"
		if strings.TrimSpace(session.Hostname) != "" {
			details += " for " + strings.TrimSpace(session.Hostname)
		}
		auditLogger.LogEvent("enrollment_expired", "", "", strings.TrimSpace(session.SourceIP), resource, models.DecisionDeny, details, false)
	})

	return pa
}

func (pa *PolicyAdministrator) ReportDeviceData(report *models.DeviceDataReport) {
	if pa == nil || pa.Devices == nil {
		return
	}
	pa.Devices.RecordDeviceData(report)
}
