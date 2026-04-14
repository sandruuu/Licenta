package main

import (
	"fmt"
	"log"
	"sync"
	"time"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
	"gopkg.in/toast.v1"
)

// HealthMonitor runs periodic health checks in the background
// and sends Windows toast notifications when status changes
type HealthMonitor struct {
	app          *App
	prevStatuses map[string]string // name -> previous status
	mu           sync.Mutex
	stopChan     chan struct{}
	interval     time.Duration
	wg           sync.WaitGroup
}

// NewHealthMonitor creates a new background monitor
func NewHealthMonitor(app *App, interval time.Duration) *HealthMonitor {
	return &HealthMonitor{
		app:          app,
		prevStatuses: make(map[string]string),
		stopChan:     make(chan struct{}),
		interval:     interval,
	}
}

// Start begins periodic health monitoring in a goroutine
func (m *HealthMonitor) Start() {
	// Do an initial scan to populate baseline
	health := m.app.GetDeviceHealth()
	m.mu.Lock()
	for _, check := range health.Checks {
		m.prevStatuses[check.Name] = check.Status
	}
	m.mu.Unlock()

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.run()
	}()
}

// Stop terminates the monitoring goroutine and waits for it to finish
func (m *HealthMonitor) Stop() {
	close(m.stopChan)
	m.wg.Wait()
}

func (m *HealthMonitor) run() {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.checkAndNotify()
		}
	}
}

func (m *HealthMonitor) checkAndNotify() {
	health := m.app.GetDeviceHealth()

	// Collect notifications under lock, detect any status change
	var toNotify []HealthCheck
	changed := false

	m.mu.Lock()
	for _, check := range health.Checks {
		prevStatus, exists := m.prevStatuses[check.Name]

		if exists && prevStatus != check.Status {
			changed = true
			// Notify if it got worse
			if isWorse(prevStatus, check.Status) {
				toNotify = append(toNotify, check)
			}
		}

		m.prevStatuses[check.Name] = check.Status
	}
	m.mu.Unlock()

	// Send notifications outside the lock to avoid blocking health checks
	for _, check := range toNotify {
		m.sendNotification(check)
	}

	// On any status change: trigger immediate cloud report + notify UI
	if changed {
		log.Printf("[MONITOR] Health status changed, triggering immediate report")
		if r := m.app.GetReporter(); r != nil {
			r.TriggerReport()
		}
		// Emit Wails event so the frontend refreshes immediately
		wailsRuntime.EventsEmit(m.app.ctx, "health:updated")
	}
}

func isWorse(prev, current string) bool {
	order := map[string]int{"good": 0, "warning": 1, "critical": 2}
	return order[current] > order[prev]
}

func (m *HealthMonitor) sendNotification(check HealthCheck) {
	title := "Device Health Alert"
	message := fmt.Sprintf("%s: %s", check.Name, check.Description)

	notification := toast.Notification{
		AppID:   "Device Health Agent",
		Title:   title,
		Message: message,
		Audio:   toast.Default,
	}

	if err := notification.Push(); err != nil {
		log.Printf("[MONITOR] Failed to send toast notification: %v", err)
	}
}
