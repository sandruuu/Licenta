// Package anomaly implements behavioral anomaly detection for the gateway.
// It monitors per-user session patterns and flags unusual behavior such as
// abnormal traffic volumes, geographic impossibility, rapid resource hopping,
// and off-hours access spikes.
package anomaly

import (
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// EventType classifies security-relevant events
type EventType string

const (
	EventConnect     EventType = "connect"
	EventAuthFailure EventType = "auth_failure"
	EventAccessDeny  EventType = "access_deny"
)

// Event is a security-relevant action recorded by the detector
type Event struct {
	Type      EventType
	UserID    string
	Username  string
	SourceIP  string
	Resource  string
	Timestamp time.Time
	BytesXfer int64
}

// Alert is produced when anomalous behavior is detected
type Alert struct {
	ID        string    `json:"id"`
	Severity  string    `json:"severity"` // "low", "medium", "high", "critical"
	Type      string    `json:"type"`
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// userProfile tracks per-user behavioral baselines
type userProfile struct {
	mu           sync.Mutex
	userID       string
	recentEvents []Event
	connectCount int // connections in current window
	failureCount int // auth failures in current window
	distinctIPs  map[string]time.Time
	windowStart  time.Time
}

// Detector monitors session behavior and flags anomalies
type Detector struct {
	mu       sync.RWMutex
	profiles map[string]*userProfile // keyed by userID
	alerts   []Alert
	alertCh  chan Alert // subscribers can receive real-time alerts

	// Dropped alert tracking
	droppedAlerts   int64     // atomic counter for dropped alerts
	lastDroppedWarn time.Time // rate-limit drop warnings to 1/min

	// Configurable thresholds
	maxConnPerWindow     int           // max connections per user per window
	maxFailuresPerWindow int           // max auth failures per window
	maxDistinctIPs       int           // max distinct source IPs per window
	windowDuration       time.Duration // sliding window size
	eventRetention       int           // max events per user profile
}

// New creates a new anomaly Detector with default thresholds
func New() *Detector {
	d := &Detector{
		profiles:             make(map[string]*userProfile),
		alertCh:              make(chan Alert, 100),
		maxConnPerWindow:     50,
		maxFailuresPerWindow: 10,
		maxDistinctIPs:       5,
		windowDuration:       10 * time.Minute,
		eventRetention:       200,
	}
	go d.cleanupLoop()
	return d
}

// RecordEvent records a security event and checks for anomalies
func (d *Detector) RecordEvent(evt Event) {
	if evt.Timestamp.IsZero() {
		evt.Timestamp = time.Now()
	}

	profile := d.getOrCreateProfile(evt.UserID)
	profile.mu.Lock()
	defer profile.mu.Unlock()

	// Reset window if expired
	if time.Since(profile.windowStart) > d.windowDuration {
		profile.connectCount = 0
		profile.failureCount = 0
		profile.distinctIPs = make(map[string]time.Time)
		profile.windowStart = time.Now()
	}

	// Track event
	profile.recentEvents = append(profile.recentEvents, evt)
	if len(profile.recentEvents) > d.eventRetention {
		profile.recentEvents = profile.recentEvents[len(profile.recentEvents)-d.eventRetention:]
	}

	// Update counters
	switch evt.Type {
	case EventConnect:
		profile.connectCount++
		if evt.SourceIP != "" {
			profile.distinctIPs[evt.SourceIP] = evt.Timestamp
		}
	case EventAuthFailure:
		profile.failureCount++
	case EventAccessDeny:
		profile.failureCount++
	}

	// Check anomaly rules
	d.checkConnectionFlood(profile, evt)
	d.checkAuthBruteForce(profile, evt)
	d.checkIPAnomaly(profile, evt)
	d.checkOffHoursAccess(profile, evt)
}

// ── Anomaly detection rules ──

func (d *Detector) checkConnectionFlood(p *userProfile, evt Event) {
	if evt.Type != EventConnect {
		return
	}
	if p.connectCount > d.maxConnPerWindow {
		d.raiseAlert(Alert{
			Severity:  "high",
			Type:      "connection_flood",
			UserID:    p.userID,
			Username:  evt.Username,
			Message:   "Abnormally high connection rate detected",
			Timestamp: time.Now(),
		})
	}
}

func (d *Detector) checkAuthBruteForce(p *userProfile, evt Event) {
	if evt.Type != EventAuthFailure && evt.Type != EventAccessDeny {
		return
	}
	if p.failureCount > d.maxFailuresPerWindow {
		d.raiseAlert(Alert{
			Severity:  "critical",
			Type:      "brute_force",
			UserID:    p.userID,
			Username:  evt.Username,
			Message:   "Possible brute-force attack: excessive auth failures",
			Timestamp: time.Now(),
		})
	}
}

func (d *Detector) checkIPAnomaly(p *userProfile, evt Event) {
	if evt.Type != EventConnect {
		return
	}
	if len(p.distinctIPs) > d.maxDistinctIPs {
		d.raiseAlert(Alert{
			Severity:  "medium",
			Type:      "ip_anomaly",
			UserID:    p.userID,
			Username:  evt.Username,
			Message:   "User accessing from unusually many distinct IPs",
			Timestamp: time.Now(),
		})
	}
}

func (d *Detector) checkOffHoursAccess(p *userProfile, evt Event) {
	if evt.Type != EventConnect {
		return
	}
	hour := evt.Timestamp.Hour()
	weekday := evt.Timestamp.Weekday()
	isOffHours := weekday == time.Saturday || weekday == time.Sunday ||
		hour < 6 || hour >= 22

	if isOffHours {
		// Only alert if there's also elevated activity
		if p.connectCount > 5 {
			d.raiseAlert(Alert{
				Severity:  "medium",
				Type:      "off_hours_spike",
				UserID:    p.userID,
				Username:  evt.Username,
				Message:   "Elevated access activity during off-hours",
				Timestamp: time.Now(),
			})
		}
	}
}

// ── Internal helpers ──

func (d *Detector) getOrCreateProfile(userID string) *userProfile {
	d.mu.RLock()
	p, ok := d.profiles[userID]
	d.mu.RUnlock()
	if ok {
		return p
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	// Double-check after write lock
	if p, ok = d.profiles[userID]; ok {
		return p
	}
	p = &userProfile{
		userID:      userID,
		distinctIPs: make(map[string]time.Time),
		windowStart: time.Now(),
	}
	d.profiles[userID] = p
	return p
}

func (d *Detector) raiseAlert(a Alert) {
	a.ID = time.Now().Format("20060102150405.000")

	d.mu.Lock()
	d.alerts = append(d.alerts, a)
	// Keep max 1000 alerts
	if len(d.alerts) > 1000 {
		d.alerts = d.alerts[len(d.alerts)-1000:]
	}
	d.mu.Unlock()

	log.Printf("[ANOMALY] ALERT [%s] %s: user=%s — %s", a.Severity, a.Type, a.Username, a.Message)

	// Non-blocking send to alert channel
	select {
	case d.alertCh <- a:
	default:
		atomic.AddInt64(&d.droppedAlerts, 1)
		d.mu.Lock()
		if time.Since(d.lastDroppedWarn) > time.Minute {
			d.lastDroppedWarn = time.Now()
			dropped := atomic.LoadInt64(&d.droppedAlerts)
			log.Printf("[ANOMALY] Alert channel full — %d alerts dropped total", dropped)
		}
		d.mu.Unlock()
	}
}

// GetActiveAlerts returns the distinct alert types and a cumulative score for a
// given user within the current detection window. The score is assigned per alert
// type: connection_flood=10, brute_force=15, ip_anomaly=10, off_hours_spike=5.
// The total is capped at 25.
func (d *Detector) GetActiveAlerts(userID string) ([]string, int) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	cutoff := time.Now().Add(-d.windowDuration)
	seen := make(map[string]bool)
	for i := len(d.alerts) - 1; i >= 0; i-- {
		a := d.alerts[i]
		if a.Timestamp.Before(cutoff) {
			break
		}
		if a.UserID == userID {
			seen[a.Type] = true
		}
	}

	if len(seen) == 0 {
		return nil, 0
	}

	weights := map[string]int{
		"connection_flood": 10,
		"brute_force":      15,
		"ip_anomaly":       10,
		"off_hours_spike":  5,
	}
	var types []string
	score := 0
	for t := range seen {
		types = append(types, t)
		score += weights[t]
	}
	if score > 25 {
		score = 25
	}
	return types, score
}

// DroppedAlerts returns the total number of alerts dropped due to channel overflow.
func (d *Detector) DroppedAlerts() int64 {
	return atomic.LoadInt64(&d.droppedAlerts)
}

func (d *Detector) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		d.mu.Lock()
		cutoff := time.Now().Add(-30 * time.Minute)
		for uid, p := range d.profiles {
			p.mu.Lock()
			if len(p.recentEvents) == 0 || p.recentEvents[len(p.recentEvents)-1].Timestamp.Before(cutoff) {
				delete(d.profiles, uid)
			}
			p.mu.Unlock()
		}
		d.mu.Unlock()
	}
}
