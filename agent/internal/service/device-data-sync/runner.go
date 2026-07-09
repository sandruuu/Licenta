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
	"sync"
	"time"

	"agent/internal/ipc"
	"agent/internal/service/enrollment"
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
	Snapshot      func() ipc.DeviceDataReport
	Watcher       Watcher
	Enrollment    EnrollmentRecordProvider
	ClientFactory ClientFactory
	Session       SessionProvider
	Clock         func() time.Time
}

type Runner struct {
	mu            sync.Mutex
	logger        *slog.Logger
	collector     Collector
	snapshot      func() ipc.DeviceDataReport
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
	lastSentSessionID    string
	lastSentFingerprint  string
	lastPeriodicReport   time.Time
	lastEnrolledDeviceID string
	lastLocalCollection  time.Time
	lastLocalReport      ipc.DeviceDataReport
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
		snapshot:      dependencies.Snapshot,
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
	if runner == nil {
		return
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.syncLocked(ctx, reason)
}

func (runner *Runner) syncLocked(ctx context.Context, reason string) {
	if ctx.Err() != nil {
		return
	}

	record, enrolled := runner.enrollmentRecord(ctx)
	if !enrolled {
		runner.resetEnrollment()
	} else if record.DeviceID != runner.lastEnrolledDeviceID {
		runner.lastEnrolledDeviceID = record.DeviceID
		runner.lastSentSessionID = ""
		runner.lastSentFingerprint = ""
		runner.lastPeriodicReport = time.Time{}
	}
	session, ok := runner.activeSession()
	uploadReady := enrolled && ok
	now := runner.clock().UTC()
	report := runner.cachedReport()
	if runner.shouldCollect(reason, uploadReady, now, report) {
		collected, err := runner.collector.Collect(ctx, record.DeviceID)
		if err != nil {
			runner.logger.Warn("Failed to collect device data for sync", "error", err)
			return
		}
		report = collected
		runner.lastLocalReport = cloneReport(collected)
		runner.lastLocalCollection = now
	}
	if !uploadReady {
		return
	}
	if len(report.Checks) == 0 {
		return
	}
	report.DeviceID = strings.TrimSpace(record.DeviceID)
	fingerprint := reportFingerprint(report)
	due := runner.lastPeriodicReport.IsZero() || now.Sub(runner.lastPeriodicReport) >= runner.config.Interval
	changed := runner.lastSentFingerprint == "" || fingerprint != runner.lastSentFingerprint || strings.TrimSpace(session.AgentSessionID) != runner.lastSentSessionID
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

	runner.lastSentSessionID = strings.TrimSpace(session.AgentSessionID)
	runner.lastSentFingerprint = fingerprint
	runner.lastPeriodicReport = now
	runner.logger.Info("Reported device data to PDP", "device_id", record.DeviceID, "agent_session_id", session.AgentSessionID, "reason", reportReason(reason, changed, due), "checks", len(report.Checks))
}

func (runner *Runner) ReportNow(ctx context.Context, record enrollment.EnrollmentRecord, session SessionContext, reason string) error {
	if runner == nil {
		return errors.New("device data sync runner is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()

	record.DeviceID = strings.TrimSpace(record.DeviceID)
	if record.DeviceID == "" {
		return errors.New("device ID is required")
	}
	session.AgentSessionID = strings.TrimSpace(session.AgentSessionID)
	session.AgentSessionToken = strings.TrimSpace(session.AgentSessionToken)
	if session.AgentSessionToken == "" {
		return errors.New("agent session token is required")
	}
	if record.DeviceID != runner.lastEnrolledDeviceID {
		runner.lastEnrolledDeviceID = record.DeviceID
		runner.lastSentSessionID = ""
		runner.lastSentFingerprint = ""
		runner.lastPeriodicReport = time.Time{}
	}

	now := runner.clock().UTC()
	report := runner.cachedReport()
	if len(report.Checks) == 0 {
		if runner.collector == nil {
			return errors.New("device data collector is not configured")
		}
		collected, err := runner.collector.Collect(ctx, record.DeviceID)
		if err != nil {
			return err
		}
		report = collected
		runner.lastLocalReport = cloneReport(collected)
		runner.lastLocalCollection = now
	}
	if len(report.Checks) == 0 {
		return errors.New("device data report is empty")
	}
	report.DeviceID = record.DeviceID
	return runner.uploadReportLocked(ctx, record, session, report, triggerReason(reason), now)
}

func (runner *Runner) enrollmentRecord(ctx context.Context) (enrollment.EnrollmentRecord, bool) {
	if runner == nil || runner.enrollment == nil {
		return enrollment.EnrollmentRecord{}, false
	}
	record, err := runner.enrollment.Record(ctx)
	if err != nil || strings.TrimSpace(record.DeviceID) == "" {
		return enrollment.EnrollmentRecord{}, false
	}
	record.DeviceID = strings.TrimSpace(record.DeviceID)
	return record, true
}

func (runner *Runner) cachedReport() ipc.DeviceDataReport {
	if runner != nil && len(runner.lastLocalReport.Checks) > 0 {
		return cloneReport(runner.lastLocalReport)
	}
	if runner == nil || runner.snapshot == nil {
		return ipc.DeviceDataReport{}
	}
	return runner.snapshot()
}

func cloneReport(report ipc.DeviceDataReport) ipc.DeviceDataReport {
	clone := report
	if report.Checks != nil {
		clone.Checks = make([]ipc.DeviceDataCheck, len(report.Checks))
		for index, check := range report.Checks {
			clone.Checks[index] = check
			if check.Details != nil {
				clone.Checks[index].Details = make(map[string]string, len(check.Details))
				for key, value := range check.Details {
					clone.Checks[index].Details[key] = value
				}
			}
		}
	}
	return clone
}

func (runner *Runner) shouldCollect(reason string, uploadReady bool, now time.Time, cached ipc.DeviceDataReport) bool {
	if runner == nil {
		return false
	}
	if len(cached.Checks) == 0 {
		return true
	}
	if uploadReady && runner.lastSentFingerprint == "" {
		return false
	}
	reason = triggerReason(reason)
	if reason == "startup" || reason == "firewall_policy" {
		return true
	}
	if uploadReady && reason != "user_authenticated" {
		return true
	}
	return runner.lastLocalCollection.IsZero() || now.Sub(runner.lastLocalCollection) >= runner.config.Interval
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

func (runner *Runner) uploadReportLocked(ctx context.Context, record enrollment.EnrollmentRecord, session SessionContext, report ipc.DeviceDataReport, reason string, now time.Time) error {
	callCtx, cancel := context.WithTimeout(ctx, runner.config.CallTimeout)
	defer cancel()
	client, err := runner.ensureClient(callCtx, record)
	if err != nil {
		return err
	}
	if err := client.ReportDeviceData(callCtx, report, session); err != nil {
		return err
	}
	runner.lastSentSessionID = strings.TrimSpace(session.AgentSessionID)
	runner.lastSentFingerprint = reportFingerprint(report)
	runner.lastPeriodicReport = now
	runner.logger.Info("Reported device data to PDP", "device_id", record.DeviceID, "agent_session_id", session.AgentSessionID, "reason", reason, "checks", len(report.Checks))
	return nil
}

func (runner *Runner) resetEnrollment() {
	if runner.lastEnrolledDeviceID != "" {
		runner.close()
	}
	runner.lastEnrolledDeviceID = ""
	runner.lastSentSessionID = ""
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
