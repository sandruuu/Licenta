package devicedatasync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"time"

	"agent/internal/service/enrollment"
	"agent/internal/shared/ipc"
)

const (
	DefaultInterval           = 30 * time.Minute
	DefaultChangeScanInterval = 30 * time.Second
	DefaultCallTimeout        = 20 * time.Second
)

type Config struct {
	Interval           time.Duration
	ChangeScanInterval time.Duration
	CallTimeout        time.Duration
}

type Collector interface {
	Collect(context.Context, string) (ipc.DeviceDataReport, error)
}

type CollectorFunc func(context.Context, string) (ipc.DeviceDataReport, error)

func (fn CollectorFunc) Collect(ctx context.Context, deviceID string) (ipc.DeviceDataReport, error) {
	return fn(ctx, deviceID)
}

type Watcher interface {
	Watch(context.Context, chan<- string) error
}

type EnrollmentRecordProvider interface {
	Record(context.Context) (enrollment.EnrollmentRecord, error)
}

type Client interface {
	ReportDeviceData(context.Context, ipc.DeviceDataReport, SessionContext) error
	Close() error
}

type ClientFactory func(context.Context, enrollment.EnrollmentRecord) (Client, error)

type SessionContext struct {
	AgentSessionID    string
	AgentSessionToken string
}

type SessionProvider func() (SessionContext, bool)

type Dependencies struct {
	Logger        *slog.Logger
	Collector     Collector
	Watcher       Watcher
	Enrollment    EnrollmentRecordProvider
	ClientFactory ClientFactory
	Session       SessionProvider
	Clock         func() time.Time
}

type Runner struct {
	logger        *slog.Logger
	collector     Collector
	watcher       Watcher
	enrollment    EnrollmentRecordProvider
	clientFactory ClientFactory
	session       SessionProvider
	clock         func() time.Time
	config        Config
	trigger       chan string

	client               Client
	clientDeviceID       string
	clientCertThumbprint string
	lastSentFingerprint  string
	lastPeriodicReport   time.Time
	lastEnrolledDeviceID string
}

func NewRunner(config Config, dependencies Dependencies) *Runner {
	if config.Interval <= 0 {
		config.Interval = DefaultInterval
	}
	if config.ChangeScanInterval <= 0 {
		config.ChangeScanInterval = DefaultChangeScanInterval
	}
	if config.CallTimeout <= 0 {
		config.CallTimeout = DefaultCallTimeout
	}
	logger := dependencies.Logger
	if logger == nil {
		logger = slog.Default()
	}
	clock := dependencies.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Runner{
		logger:        logger,
		collector:     dependencies.Collector,
		watcher:       dependencies.Watcher,
		enrollment:    dependencies.Enrollment,
		clientFactory: dependencies.ClientFactory,
		session:       dependencies.Session,
		clock:         clock,
		config:        config,
		trigger:       make(chan string, 8),
	}
}

func (runner *Runner) Run(ctx context.Context) {
	if runner == nil {
		return
	}
	if runner.collector == nil {
		runner.logger.Info("Device data sync disabled: no device data collector is configured")
		return
	}
	if runner.enrollment == nil {
		runner.logger.Info("Device data sync disabled: no enrollment store is configured")
		return
	}
	if runner.watcher != nil {
		go func() {
			if err := runner.watcher.Watch(ctx, runner.trigger); err != nil && ctx.Err() == nil {
				runner.logger.Warn("Device data watcher stopped", "error", err)
			}
		}()
	}
	ticker := time.NewTicker(runner.config.ChangeScanInterval)
	defer ticker.Stop()
	defer runner.close()

	runner.sync(ctx, "startup")
	for {
		select {
		case <-ctx.Done():
			return
		case reason := <-runner.trigger:
			runner.sync(ctx, triggerReason(reason))
		case <-ticker.C:
			runner.sync(ctx, "scan")
		}
	}
}

func (runner *Runner) Trigger(reason string) bool {
	if runner == nil || runner.trigger == nil {
		return false
	}
	select {
	case runner.trigger <- triggerReason(reason):
		return true
	default:
		return false
	}
}

func (runner *Runner) sync(ctx context.Context, reason string) {
	if ctx.Err() != nil {
		return
	}

	record, err := runner.enrollment.Record(ctx)
	if err != nil {
		runner.resetEnrollment()
		return
	}
	if strings.TrimSpace(record.DeviceID) == "" {
		runner.resetEnrollment()
		return
	}
	if record.DeviceID != runner.lastEnrolledDeviceID {
		runner.lastEnrolledDeviceID = record.DeviceID
		runner.lastSentFingerprint = ""
		runner.lastPeriodicReport = time.Time{}
	}
	session, ok := runner.activeSession()
	if !ok {
		runner.lastSentFingerprint = ""
		runner.lastPeriodicReport = time.Time{}
		return
	}

	report, err := runner.collector.Collect(ctx, record.DeviceID)
	if err != nil {
		runner.logger.Warn("Failed to collect device data for sync", "error", err)
		return
	}
	report.DeviceID = strings.TrimSpace(record.DeviceID)
	fingerprint := reportFingerprint(report)
	now := runner.clock().UTC()
	due := runner.lastPeriodicReport.IsZero() || now.Sub(runner.lastPeriodicReport) >= runner.config.Interval
	changed := runner.lastSentFingerprint == "" || fingerprint != runner.lastSentFingerprint
	if !due && !changed {
		return
	}

	callCtx, cancel := context.WithTimeout(ctx, runner.config.CallTimeout)
	defer cancel()
	client, err := runner.ensureClient(callCtx, record)
	if err != nil {
		runner.logger.Warn("Failed to prepare device data sync client", "error", err)
		return
	}
	if err := client.ReportDeviceData(callCtx, report, session); err != nil {
		runner.logger.Warn("Failed to report device data to PDP", "device_id", record.DeviceID, "reason", reason, "error", err)
		return
	}

	runner.lastSentFingerprint = fingerprint
	runner.lastPeriodicReport = now
	runner.logger.Info("Reported device data to PDP", "device_id", record.DeviceID, "agent_session_id", session.AgentSessionID, "reason", reportReason(reason, changed, due), "checks", len(report.Checks))
}

func (runner *Runner) activeSession() (SessionContext, bool) {
	if runner == nil || runner.session == nil {
		return SessionContext{}, false
	}
	session, ok := runner.session()
	if !ok || strings.TrimSpace(session.AgentSessionToken) == "" {
		return SessionContext{}, false
	}
	session.AgentSessionID = strings.TrimSpace(session.AgentSessionID)
	session.AgentSessionToken = strings.TrimSpace(session.AgentSessionToken)
	return session, true
}

func (runner *Runner) ensureClient(ctx context.Context, record enrollment.EnrollmentRecord) (Client, error) {
	if runner.client != nil && runner.clientDeviceID == record.DeviceID && runner.clientCertThumbprint == record.DeviceCertThumbprint {
		return runner.client, nil
	}
	runner.close()
	if runner.clientFactory == nil {
		return nil, errors.New("device data sync client factory is not configured")
	}
	client, err := runner.clientFactory(ctx, record)
	if err != nil {
		return nil, err
	}
	runner.client = client
	runner.clientDeviceID = record.DeviceID
	runner.clientCertThumbprint = record.DeviceCertThumbprint
	return client, nil
}

func (runner *Runner) resetEnrollment() {
	if runner.lastEnrolledDeviceID != "" {
		runner.close()
	}
	runner.lastEnrolledDeviceID = ""
	runner.lastSentFingerprint = ""
	runner.lastPeriodicReport = time.Time{}
}

func (runner *Runner) close() {
	if runner.client != nil {
		_ = runner.client.Close()
		runner.client = nil
	}
	runner.clientDeviceID = ""
	runner.clientCertThumbprint = ""
}

func reportReason(reason string, changed, due bool) string {
	if changed {
		if reason == "enrollment" || reason == "startup" {
			return reason
		}
		return "device_data_changed"
	}
	if due {
		return "periodic"
	}
	return reason
}

func triggerReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return "event"
	}
	return reason
}

func reportFingerprint(report ipc.DeviceDataReport) string {
	type postureCheck struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	normalized := struct {
		DeviceID string         `json:"device_id"`
		Checks   []postureCheck `json:"checks"`
	}{
		DeviceID: strings.TrimSpace(report.DeviceID),
	}
	for _, check := range report.Checks {
		name := strings.ToLower(strings.TrimSpace(check.Name))
		if name == "" {
			continue
		}
		normalized.Checks = append(normalized.Checks, postureCheck{
			Name:   name,
			Status: strings.ToLower(strings.TrimSpace(check.Status)),
		})
	}
	sort.SliceStable(normalized.Checks, func(i, j int) bool {
		left := normalized.Checks[i]
		right := normalized.Checks[j]
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		return left.Status < right.Status
	})
	data, _ := json.Marshal(normalized)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
