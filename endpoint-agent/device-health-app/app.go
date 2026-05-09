package main

import (
	"context"
	"device-health-app/collectors"
	"device-health-app/tpmauth"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App struct
type App struct {
	ctx      context.Context
	monitor  *HealthMonitor
	localAPI *LocalAPI
	cfg      *HealthAppConfig

	reporterMu sync.Mutex
	reporter   *CloudReporter
	pushPoller *PushPoller

	wg sync.WaitGroup
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// GetReporter safely returns the current reporter (may be nil during enrollment)
func (a *App) GetReporter() *CloudReporter {
	a.reporterMu.Lock()
	defer a.reporterMu.Unlock()
	return a.reporter
}

// setReporter safely sets the reporter
func (a *App) setReporter(r *CloudReporter) {
	a.reporterMu.Lock()
	defer a.reporterMu.Unlock()
	a.reporter = r
}

// startup is called when the app starts
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	// Load configuration
	a.cfg = LoadHealthAppConfig("health-config.json")

	// Start background health monitoring (every 30 seconds) — detects changes
	// and triggers immediate cloud reports + UI updates via Wails events
	a.monitor = NewHealthMonitor(a, 30*time.Second)
	a.monitor.Start()

	// Start cloud reporter — sends health data directly to the cloud.
	// The connect-app does NOT send health data; this is the responsibility
	// of the device-health-app.
	//
	// Uses TPM-backed (or software fallback) key for enrollment.
	// KeyManager checks for existing keys before creating new ones.
	dataDir := a.cfg.DataDir
	if dataDir == "" {
		dataDir = "./data"
	}

	km, err := tpmauth.NewKeyManager(dataDir)
	if err != nil {
		log.Printf("[ENROLLMENT] Key manager init failed: %v", err)
	} else {
		// Auto-derive device_id from TPM Endorsement Key (or MachineGuid fallback)
		if a.cfg.DeviceID == "" {
			deviceID, err := km.DeviceFingerprint()
			if err != nil {
				log.Printf("[ENROLLMENT] Failed to derive device ID: %v", err)
			} else {
				a.cfg.DeviceID = deviceID
				log.Printf("[ENROLLMENT] Device ID derived: %s (tpm=%v)", a.cfg.DeviceID, km.IsTPM())
			}
		}

		a.wg.Add(1)
		go func() {
			defer a.wg.Done()
			a.runEnrollment(km, dataDir)
		}()
	}

	// Start local API so connect-app can verify this agent is running
	// LocalAPI reads reporter from app dynamically (thread-safe)
	a.localAPI = NewLocalAPI(a, a.cfg.LocalAPIAddr)
	a.localAPI.Start()

	// S5.3 — mutual watchdog poll. Connect-app exposes /watchdog on
	// 127.0.0.1:12082; if that endpoint stops responding the user is
	// running with no posture-enforcing tunnel and we want a clear
	// audit trail.
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		startWatchdogClient(a.ctx, "http://127.0.0.1:12082/watchdog", "connect-app")
	}()
}

// shutdown is called when the app is closing
func (a *App) shutdown(ctx context.Context) {
	if a.pushPoller != nil {
		a.pushPoller.Stop()
	}
	if a.localAPI != nil {
		a.localAPI.Stop()
	}
	r := a.GetReporter()
	if r != nil {
		r.Stop()
	}
	if a.monitor != nil {
		a.monitor.Stop()
	}
	a.wg.Wait()
}

// RespondToPush handles the user's approve/deny decision from the React UI.
// Bound to Wails so the frontend can call it directly.
func (a *App) RespondToPush(challengeID, decision string) string {
	if a.pushPoller == nil {
		return "Push poller not initialized"
	}
	if err := a.pushPoller.RespondToChallenge(challengeID, decision); err != nil {
		return err.Error()
	}
	return ""
}

// HideWindow hides the window to tray-like background mode
func (a *App) HideWindow() {
	wailsRuntime.WindowHide(a.ctx)
}

// ShowWindow brings the window back
func (a *App) ShowWindow() {
	wailsRuntime.WindowShow(a.ctx)
}

// runEnrollment performs device enrollment in the background and starts the
// cloud reporter once a certificate is obtained. This avoids blocking the Wails UI.
func (a *App) runEnrollment(km *tpmauth.KeyManager, dataDir string) {
	hostname, _ := os.Hostname()
	deviceID := a.cfg.DeviceID

	// Use the Wails app context — cancelled on shutdown
	enrollCtx, cancel := context.WithTimeout(a.ctx, 30*time.Minute)
	defer cancel()

	result, err := tpmauth.EnrollAndWait(enrollCtx, km, a.cfg.CloudURL, a.cfg.ServerCAFile, a.cfg.CloudCertSHA256, deviceID, hostname, dataDir)
	if err != nil {
		log.Printf("[ENROLLMENT] Enrollment failed: %v", err)
		return
	}
	log.Printf("[ENROLLMENT] Device enrolled (tpm=%v)", km.IsTPM())

	// Start background auto-renewal for short-lived certs (24h validity, renew at 12h)
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		tpmauth.StartAutoRenewal(a.ctx, km, a.cfg.CloudURL, a.cfg.ServerCAFile, a.cfg.CloudCertSHA256, deviceID, hostname, dataDir)
	}()

	reporter, err := NewCloudReporterWithSigner(a, a.cfg, result.CertPEM, result.CAPEM, km.Signer())
	if err != nil {
		log.Printf("[REPORTER] Failed to initialize cloud reporter with enrollment cert: %v", err)
		return
	}
	a.setReporter(reporter)
	reporter.Start()

	// Start push challenge poller (shares the same mTLS HTTP client)
	a.pushPoller = NewPushPoller(a, a.cfg.CloudURL, reporter.httpClient)
	a.pushPoller.Start()
}

// GetDeviceHealth collects all device health information and returns it.
// Each collector runs concurrently with an independent timeout so a single
// hung Win32 / WMI call cannot block the whole posture report (which would
// otherwise stall the gateway's authorize chain). Timed-out collectors are
// reported as "warning" status with a 50/100 score, matching the policy
// engine's treatment of unknown signals.
func (a *App) GetDeviceHealth() DeviceHealth {
	const collectorBudget = 10 * time.Second

	health := DeviceHealth{
		CollectedAt: time.Now().Format("2006-01-02 15:04:05"),
	}

	// Hostname is cheap and synchronous — no need for a timeout.
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "Unknown"
	}
	health.Hostname = hostname

	// Each collector returns its HealthCheck; the OS check also feeds health.OS.
	type slot struct {
		index int
		check HealthCheck
		osTag string // populated by the OS collector only
	}
	results := make([]slot, 5)

	var osTagFromOS string
	var wg sync.WaitGroup

	runCollector := func(idx int, name string, build func() (HealthCheck, string)) {
		defer wg.Done()
		ch := make(chan struct {
			hc    HealthCheck
			osTag string
		}, 1)
		go func() {
			hc, tag := build()
			ch <- struct {
				hc    HealthCheck
				osTag string
			}{hc, tag}
		}()
		select {
		case r := <-ch:
			results[idx] = slot{index: idx, check: r.hc, osTag: r.osTag}
		case <-time.After(collectorBudget):
			log.Printf("[HEALTH] Collector %q timed out after %s", name, collectorBudget)
			results[idx] = slot{
				index: idx,
				check: HealthCheck{
					Name:        name,
					Status:      "warning",
					Description: fmt.Sprintf("Collector timed out after %s", collectorBudget),
					Details: map[string]string{
						"timeout": collectorBudget.String(),
					},
				},
			}
		}
	}

	wg.Add(5)
	go runCollector(0, "Operating System", func() (HealthCheck, string) {
		osInfo := collectors.CollectOSInfo()
		return HealthCheck{
			Name:        "Operating System",
			Status:      "good",
			Description: osInfo.Name,
			Details: map[string]string{
				"Version":      osInfo.Version,
				"Build":        osInfo.Build,
				"Architecture": osInfo.Architecture,
				"Uptime":       osInfo.Uptime,
			},
		}, osInfo.Name
	})
	go runCollector(1, "Firewall", func() (HealthCheck, string) {
		fwStatus := collectors.CollectFirewallStatus()
		fwCheck := HealthCheck{
			Name: "Firewall",
			Details: map[string]string{
				"Domain Profile":  boolToOnOff(fwStatus.DomainProfile),
				"Private Profile": boolToOnOff(fwStatus.PrivateProfile),
				"Public Profile":  boolToOnOff(fwStatus.PublicProfile),
			},
		}
		if fwStatus.AllEnabled {
			fwCheck.Status = "good"
			fwCheck.Description = "All firewall profiles are active"
		} else if fwStatus.DomainProfile || fwStatus.PrivateProfile || fwStatus.PublicProfile {
			fwCheck.Status = "warning"
			fwCheck.Description = "Some firewall profiles are disabled"
		} else {
			fwCheck.Status = "critical"
			fwCheck.Description = "Firewall is completely disabled"
		}
		return fwCheck, ""
	})
	go runCollector(2, "Antivirus", func() (HealthCheck, string) {
		avInfo := collectors.CollectAntivirusInfo()
		avCheck := HealthCheck{
			Name:    "Antivirus",
			Details: map[string]string{},
		}
		if !avInfo.Found {
			avCheck.Status = "critical"
			avCheck.Description = "No antivirus product detected"
		} else {
			avCheck.Details["Product"] = avInfo.ProductName
			avCheck.Details["Real-time Protection"] = boolToOnOff(avInfo.Enabled)
			avCheck.Details["Definitions"] = boolToStatus(avInfo.UpToDate, "Up to date", "Out of date")
			if avInfo.Enabled && avInfo.UpToDate {
				avCheck.Status = "good"
				avCheck.Description = avInfo.ProductName + " is active and up to date"
			} else if avInfo.Enabled {
				avCheck.Status = "warning"
				avCheck.Description = avInfo.ProductName + " — definitions may be outdated"
			} else {
				avCheck.Status = "critical"
				avCheck.Description = avInfo.ProductName + " — real-time protection is disabled"
			}
		}
		return avCheck, ""
	})
	go runCollector(3, "Disk Encryption", func() (HealthCheck, string) {
		diskInfo := collectors.CollectDiskEncryption()
		diskCheck := HealthCheck{
			Name: "Disk Encryption",
			Details: map[string]string{
				"Protection":        diskInfo.ProtectionStatus,
				"Encryption Method": diskInfo.EncryptionMethod,
				"Volume Status":     diskInfo.VolumeStatus,
			},
		}
		if diskInfo.IsEncrypted {
			diskCheck.Status = "good"
			diskCheck.Description = "BitLocker protection is active on C:"
		} else if diskInfo.ProtectionStatus == "Unknown" {
			diskCheck.Status = "warning"
			diskCheck.Description = "Unable to determine encryption status (run as admin)"
		} else {
			diskCheck.Status = "critical"
			diskCheck.Description = "System drive is not encrypted"
		}
		return diskCheck, ""
	})
	go runCollector(4, "Password & Lock", func() (HealthCheck, string) {
		pwInfo := collectors.CollectPasswordInfo()
		pwCheck := HealthCheck{
			Name: "Password & Lock",
			Details: map[string]string{
				"Password Set": boolToYesNo(pwInfo.PasswordSet),
				"Screen Lock":  boolToYesNo(pwInfo.ScreenLockSet),
				"Lock Timeout": pwInfo.LockTimeout,
			},
		}
		if pwInfo.PasswordSet && pwInfo.ScreenLockSet {
			pwCheck.Status = "good"
			pwCheck.Description = "Password is set and screen lock is enabled"
		} else if pwInfo.PasswordSet {
			pwCheck.Status = "warning"
			pwCheck.Description = "Password is set but screen lock may not be configured"
		} else {
			pwCheck.Status = "critical"
			pwCheck.Description = "No password set for this account"
		}
		return pwCheck, ""
	})
	wg.Wait()

	for _, r := range results {
		if r.osTag != "" {
			osTagFromOS = r.osTag
		}
		health.Checks = append(health.Checks, r.check)
	}
	health.OS = osTagFromOS

	// Calculate overall score
	health.OverallScore = calculateScore(health.Checks)

	return health
}

func calculateScore(checks []HealthCheck) int {
	if len(checks) == 0 {
		return 0
	}
	total := 0
	for _, c := range checks {
		switch c.Status {
		case "good":
			total += 100
		case "warning":
			total += 50
		case "critical":
			total += 0
		}
	}
	return total / len(checks)
}

func boolToOnOff(b bool) string {
	if b {
		return "ON"
	}
	return "OFF"
}

func boolToYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

func boolToStatus(b bool, trueVal, falseVal string) string {
	if b {
		return trueVal
	}
	return falseVal
}

// startWatchdogClient polls a sibling process every 30s and logs a
// warning after three consecutive failures (S5.3 mutual watchdog).
func startWatchdogClient(ctx context.Context, target, name string) {
	client := &http.Client{Timeout: 3 * time.Second}
	consecutiveFailures := 0
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
			resp, err := client.Do(req)
			if err != nil || resp.StatusCode >= 500 {
				if resp != nil {
					resp.Body.Close()
				}
				consecutiveFailures++
				if consecutiveFailures == 3 {
					log.Printf("[WATCHDOG] sibling %s not responding at %s (failures=%d)", name, target, consecutiveFailures)
				}
			} else {
				resp.Body.Close()
				if consecutiveFailures >= 3 {
					log.Printf("[WATCHDOG] sibling %s recovered", name)
				}
				consecutiveFailures = 0
			}
		}
	}
}
