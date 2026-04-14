package main

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// CloudReporter periodically sends device health reports directly to the cloud.
// The device-health-app is responsible for transmitting health data — the connect-app
// does NOT send this data. The cloud uses the reported health to make policy decisions
// when the gateway requests authorization.
type CloudReporter struct {
	app         *App
	cloudURL    string
	deviceID    string
	interval    time.Duration
	httpClient  *http.Client
	stopChan    chan struct{}
	triggerChan chan struct{}
	mu          sync.Mutex
	lastReport  *CloudHealthReport
	lastSentAt  time.Time
	lastError   error
}

// CloudHealthReport is the payload sent to the cloud's device health endpoint.
// It mirrors the cloud's models.DeviceHealthReport structure.
type CloudHealthReport struct {
	DeviceID     string             `json:"device_id"`
	Hostname     string             `json:"hostname"`
	OS           string             `json:"os"`
	Checks       []CloudHealthCheck `json:"checks"`
	OverallScore int                `json:"overall_score"`
	ReportedAt   time.Time          `json:"reported_at"`
}

// CloudHealthCheck mirrors the cloud's models.HealthCheck
type CloudHealthCheck struct {
	Name        string            `json:"name"`
	Status      string            `json:"status"`
	Description string            `json:"description"`
	Details     map[string]string `json:"details"`
}

// ReporterStatus is exposed via the local API so connect-app can verify
// that health data is being sent to the cloud.
type ReporterStatus struct {
	Running    bool   `json:"running"`
	DeviceID   string `json:"device_id"`
	CloudURL   string `json:"cloud_url"`
	LastSentAt string `json:"last_sent_at,omitempty"`
	LastError  string `json:"last_error,omitempty"`
	LastScore  int    `json:"last_score"`
}

// NewCloudReporterWithSigner creates a reporter using a crypto.Signer (TPM or software)
// and PEM-encoded certificate from the enrollment flow, instead of loading from files.
func NewCloudReporterWithSigner(app *App, cfg *HealthAppConfig, certPEM, caPEM []byte, signer crypto.Signer) (*CloudReporter, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}

	// Server CA
	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse enrollment CA")
		}
		tlsConfig.RootCAs = pool
	} else if cfg.ServerCAFile != "" {
		caCert, err := os.ReadFile(cfg.ServerCAFile)
		if err != nil {
			return nil, fmt.Errorf("read server CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse server CA")
		}
		tlsConfig.RootCAs = pool
	}

	if strings.TrimSpace(cfg.ServerName) != "" {
		tlsConfig.ServerName = strings.TrimSpace(cfg.ServerName)
	}

	// Client certificate with crypto.Signer as private key
	var tlsCert tls.Certificate
	for rest := certPEM; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		tlsCert.Certificate = append(tlsCert.Certificate, block.Bytes)
	}
	if len(tlsCert.Certificate) == 0 {
		return nil, fmt.Errorf("no certificates in enrollment PEM")
	}

	// Validate the client certificate
	parsedCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse client certificate: %w", err)
	}
	now := time.Now()
	if now.Before(parsedCert.NotBefore) || now.After(parsedCert.NotAfter) {
		return nil, fmt.Errorf("client certificate not valid: notBefore=%s notAfter=%s",
			parsedCert.NotBefore.Format(time.RFC3339), parsedCert.NotAfter.Format(time.RFC3339))
	}
	hasClientAuth := false
	for _, usage := range parsedCert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
			break
		}
	}
	if !hasClientAuth {
		log.Printf("[REPORTER] Warning: client certificate lacks ClientAuth EKU")
	}

	tlsCert.PrivateKey = signer
	tlsConfig.Certificates = []tls.Certificate{tlsCert}

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return &CloudReporter{
		app:         app,
		cloudURL:    cfg.CloudURL,
		deviceID:    cfg.DeviceID,
		interval:    time.Duration(cfg.ReportIntervalSeconds) * time.Second,
		httpClient:  httpClient,
		stopChan:    make(chan struct{}),
		triggerChan: make(chan struct{}, 1),
	}, nil
}

// TriggerReport requests an immediate report (non-blocking).
// Used by the health monitor when a status change is detected.
func (cr *CloudReporter) TriggerReport() {
	select {
	case cr.triggerChan <- struct{}{}:
	default:
		// already pending
	}
}

// Start begins periodic reporting in a background goroutine.
// Reports are sent at the configured interval (default 5 min) AND immediately
// when triggered by a health status change event via TriggerReport().
// Uses exponential backoff on failures (up to 5 minutes), resets on success.
func (cr *CloudReporter) Start() {
	go func() {
		consecutiveFailures := 0
		maxBackoff := 5 * time.Minute

		// Send initial report immediately
		cr.sendReport(&consecutiveFailures)

		ticker := time.NewTicker(cr.interval)
		defer ticker.Stop()

		for {
			select {
			case <-cr.stopChan:
				return
			case <-cr.triggerChan:
				cr.sendReport(&consecutiveFailures)
				ticker.Reset(cr.interval) // reset timer after event-driven send
			case <-ticker.C:
				if consecutiveFailures > 0 {
					backoff := cr.interval * time.Duration(1<<consecutiveFailures)
					if backoff > maxBackoff {
						backoff = maxBackoff
					}
					ticker.Reset(backoff)
				} else {
					ticker.Reset(cr.interval)
				}
				cr.sendReport(&consecutiveFailures)
			}
		}
	}()

	log.Printf("[REPORTER] Cloud reporter started: cloud=%s device=%s interval=%v",
		cr.cloudURL, cr.deviceID, cr.interval)
}

// Stop terminates the reporting goroutine
func (cr *CloudReporter) Stop() {
	close(cr.stopChan)
	log.Println("[REPORTER] Cloud reporter stopped")
}

// GetStatus returns the current reporter status (used by local API)
func (cr *CloudReporter) GetStatus() ReporterStatus {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	status := ReporterStatus{
		Running:  true,
		DeviceID: cr.deviceID,
		CloudURL: cr.cloudURL,
	}

	if !cr.lastSentAt.IsZero() {
		status.LastSentAt = cr.lastSentAt.Format(time.RFC3339)
	}
	if cr.lastError != nil {
		status.LastError = cr.lastError.Error()
	}
	if cr.lastReport != nil {
		status.LastScore = cr.lastReport.OverallScore
	}

	return status
}

// sendReport collects device health and POSTs it to the cloud
func (cr *CloudReporter) sendReport(consecutiveFailures *int) {
	health := cr.app.GetDeviceHealth()

	hostname, _ := os.Hostname()

	report := &CloudHealthReport{
		DeviceID:     cr.deviceID,
		Hostname:     hostname,
		OS:           health.OS,
		OverallScore: health.OverallScore,
		ReportedAt:   time.Now(),
		Checks:       make([]CloudHealthCheck, 0, len(health.Checks)),
	}

	for _, c := range health.Checks {
		report.Checks = append(report.Checks, CloudHealthCheck{
			Name:        c.Name,
			Status:      c.Status,
			Description: c.Description,
			Details:     c.Details,
		})
	}

	body, err := json.Marshal(report)
	if err != nil {
		cr.mu.Lock()
		cr.lastError = fmt.Errorf("marshal error: %w", err)
		cr.mu.Unlock()
		log.Printf("[REPORTER] Failed to marshal health report: %v", err)
		*consecutiveFailures++
		return
	}

	url := cr.cloudURL + "/api/device/health-report"
	resp, err := cr.httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		cr.mu.Lock()
		cr.lastError = fmt.Errorf("cloud unreachable: %w", err)
		cr.mu.Unlock()
		log.Printf("[REPORTER] Failed to send health report to cloud: %v", err)
		*consecutiveFailures++
		return
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		cr.mu.Lock()
		cr.lastError = fmt.Errorf("cloud returned HTTP %d", resp.StatusCode)
		cr.mu.Unlock()
		log.Printf("[REPORTER] Cloud rejected health report: HTTP %d", resp.StatusCode)
		*consecutiveFailures++
		return
	}

	cr.mu.Lock()
	cr.lastReport = report
	cr.lastSentAt = time.Now()
	cr.lastError = nil
	cr.mu.Unlock()

	*consecutiveFailures = 0

	log.Printf("[REPORTER] Health report sent to cloud: score=%d checks=%d",
		report.OverallScore, len(report.Checks))
}
