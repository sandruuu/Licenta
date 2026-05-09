package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
	"gopkg.in/toast.v1"
)

// PushChallenge mirrors the cloud's models.PushChallenge.
type PushChallenge struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	DeviceID  string `json:"device_id"`
	SourceIP  string `json:"source_ip"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
}

// PushPoller polls the cloud for pending push MFA challenges and emits
// Wails events so the React frontend can show an approval dialog.
type PushPoller struct {
	app        *App
	cloudURL   string
	httpClient *http.Client // shared mTLS client from CloudReporter
	stopChan   chan struct{}
	interval   time.Duration
}

// NewPushPoller creates a poller that shares the reporter's mTLS HTTP client.
func NewPushPoller(app *App, cloudURL string, httpClient *http.Client) *PushPoller {
	return &PushPoller{
		app:        app,
		cloudURL:   cloudURL,
		httpClient: httpClient,
		stopChan:   make(chan struct{}),
		interval:   30 * time.Second, // SSE handles real-time delivery; this is a fallback resync
	}
}

// Start begins the polling loop in a background goroutine.
func (pp *PushPoller) Start() {
	go pp.pollLoop()
	go pp.sseLoop()
	log.Printf("[PUSH] Push poller started (interval=%v, SSE=on)", pp.interval)
}

// Stop terminates the polling loop.
func (pp *PushPoller) Stop() {
	close(pp.stopChan)
	log.Println("[PUSH] Push poller stopped")
}

// sseLoop maintains a long-lived SSE connection to /api/device/push-events.
// On each `event:` line we trigger an immediate poll() to fetch the
// authoritative challenge data — the SSE event itself is just a
// notification, not the source of truth (matches gateway pattern).
//
// Connection failures back off exponentially up to 30s so a cloud outage
// does not turn into a tight reconnect loop. Polling continues as a
// fallback regardless of SSE state, so this is purely a latency
// optimisation (3s → sub-second).
func (pp *PushPoller) sseLoop() {
	backoff := 1 * time.Second
	const maxBackoff = 30 * time.Second
	url := pp.cloudURL + "/api/device/push-events"

	for {
		select {
		case <-pp.stopChan:
			return
		default:
		}

		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return
		}
		req.Header.Set("Accept", "text/event-stream")
		req.Header.Set("Cache-Control", "no-cache")
		resp, err := pp.httpClient.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			backoff = 1 * time.Second // reset on success
			pp.consumeSSE(resp.Body)
			resp.Body.Close()
		} else {
			if resp != nil {
				resp.Body.Close()
			}
		}

		select {
		case <-pp.stopChan:
			return
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// consumeSSE reads SSE frames and on each event triggers an immediate
// poll. We deliberately do not parse the payload — re-using poll()
// guarantees we apply the same filtering, toast and Wails-event logic
// regardless of delivery channel.
func (pp *PushPoller) consumeSSE(body io.Reader) {
	buf := make([]byte, 4096)
	for {
		select {
		case <-pp.stopChan:
			return
		default:
		}
		n, err := body.Read(buf)
		if n > 0 {
			// Any data on the stream means "something changed" — heartbeat
			// comments are harmless to react to (poll just returns false).
			pp.poll()
		}
		if err != nil {
			return
		}
	}
}

func (pp *PushPoller) pollLoop() {
	interval := pp.interval
	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-pp.stopChan:
			return
		case <-timer.C:
			hadWork := pp.poll()
			if hadWork {
				interval = pp.interval // reset to base on activity
			} else {
				interval = interval * 2
				if interval > 30*time.Second {
					interval = 30 * time.Second
				}
			}
			timer.Reset(interval)
		}
	}
}

func (pp *PushPoller) poll() bool {
	url := pp.cloudURL + "/api/device/push-challenges"

	resp, err := pp.httpClient.Get(url)
	if err != nil {
		// Silently ignore — connection may not be ready yet
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	var result struct {
		Challenges []PushChallenge `json:"challenges"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return false
	}

	if len(result.Challenges) == 0 {
		return false
	}

	// Emit a Wails event for each pending challenge so the React UI can show a dialog
	for _, ch := range result.Challenges {
		log.Printf("[PUSH] Pending challenge: id=%s user=%s from=%s", ch.ID, ch.Username, ch.SourceIP)
		wailsRuntime.EventsEmit(pp.app.ctx, "push:challenge", ch)
	}

	// Also show a Windows toast notification for the most recent challenge
	ch := result.Challenges[0]
	showPushToast(ch.Username, ch.SourceIP)
	return true
}

// RespondToChallenge sends an approve/deny decision to the cloud.
// Called from the Wails frontend via App binding.
func (pp *PushPoller) RespondToChallenge(challengeID, decision string) error {
	payload, _ := json.Marshal(map[string]string{
		"challenge_id": challengeID,
		"decision":     decision,
	})

	url := pp.cloudURL + "/api/device/push-challenges/respond"
	resp, err := pp.httpClient.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("send push response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("push response rejected (HTTP %d): %s", resp.StatusCode, body)
	}

	log.Printf("[PUSH] Challenge %s: %s", challengeID, decision)
	return nil
}

// showPushToast displays a Windows toast notification for the push challenge.
func showPushToast(username, sourceIP string) {
	notification := toast.Notification{
		AppID:   "Device Health Agent",
		Title:   "MFA Push Request",
		Message: fmt.Sprintf("User: %s\nFrom: %s\nOpen the Device Health app to approve or deny.", username, sourceIP),
		Audio:   toast.Default,
	}
	if err := notification.Push(); err != nil {
		log.Printf("[PUSH] Toast notification failed: %v", err)
	}
}
