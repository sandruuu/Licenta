package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// rateLimiter implements a simple sliding window rate limiter.
type rateLimiter struct {
	mu       sync.Mutex
	requests []time.Time
	maxReqs  int
	window   time.Duration
}

func newRateLimiter(maxReqs int, window time.Duration) *rateLimiter {
	return &rateLimiter{maxReqs: maxReqs, window: window}
}

func (rl *rateLimiter) allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-rl.window)
	// Remove expired entries
	valid := rl.requests[:0]
	for _, t := range rl.requests {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	rl.requests = valid
	if len(rl.requests) >= rl.maxReqs {
		return false
	}
	rl.requests = append(rl.requests, now)
	return true
}

// LocalAPI exposes a small HTTP server on localhost so that the Cloud login
// page (via browser JavaScript) can verify that the device-health-app is
// running and check its status before allowing the user to authenticate.
// The Cloud login page fetches http://127.0.0.1:12080/health from the browser.
type LocalAPI struct {
	app     *App
	server  *http.Server
	addr    string
	limiter *rateLimiter
}

// StatusResponse is returned on GET /status
type StatusResponse struct {
	Running        bool           `json:"running"`
	DeviceID       string         `json:"device_id"`
	Hostname       string         `json:"hostname"`
	OverallScore   int            `json:"overall_score"`
	Checks         []HealthCheck  `json:"checks"`
	ReporterStatus ReporterStatus `json:"reporter_status"`
}

// NewLocalAPI creates a new local API server.
// addr is the listen address (e.g. "127.0.0.1:12080").
func NewLocalAPI(app *App, addr string) *LocalAPI {
	api := &LocalAPI{
		app:     app,
		addr:    addr,
		limiter: newRateLimiter(5, time.Minute), // strict rate limit for local API
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/status", api.corsMiddleware(api.handleStatus))
	mux.HandleFunc("/health", api.corsMiddleware(api.handleHealth))

	api.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	return api
}

// corsMiddleware adds CORS headers so the Cloud login page (running on a
// different origin, e.g. https://localhost:8443) can fetch these endpoints
// from the browser. Only allows requests from localhost origins.
func (api *LocalAPI) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Rate limiting
		if !api.limiter.allow() {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// DNS rebinding protection: reject requests with non-localhost Host header
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host != "localhost" && host != "127.0.0.1" && host != "[::1]" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		origin := r.Header.Get("Origin")
		if origin != "" && isAllowedOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		}

		// Handle preflight
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next(w, r)
	}
}

// isAllowedOrigin checks whether the origin is a localhost variant
func isAllowedOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "[::1]"
}

// Start begins listening for local API requests in a background goroutine.
// Only listens on localhost — not accessible from the network.
func (api *LocalAPI) Start() {
	go func() {
		log.Printf("[LOCAL-API] Listening on %s", api.addr)
		if err := api.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[LOCAL-API] Server error: %v", err)
		}
	}()
}

// Stop gracefully shuts down the local API server
func (api *LocalAPI) Stop() {
	if api.server != nil {
		api.server.Close()
	}
}

// handleStatus returns the full status including health data and reporter state.
// Used by the Cloud login page to verify the health agent is running and reporting.
func (api *LocalAPI) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	health := api.app.GetDeviceHealth()

	resp := StatusResponse{
		Running:      true,
		DeviceID:     api.app.cfg.DeviceID,
		Hostname:     health.Hostname,
		OverallScore: health.OverallScore,
		Checks:       health.Checks,
	}

	reporter := api.app.GetReporter()
	if reporter != nil {
		resp.DeviceID = reporter.deviceID
		status := reporter.GetStatus()
		status.CloudURL = "" // redact internal URL from local API
		resp.ReporterStatus = status
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("[LOCAL-API] Failed to encode status response: %v", err)
	}
}

// handleHealth is a simple liveness check endpoint.
// Returns 200 if the app is running — used by the Cloud login page for a quick check.
func (api *LocalAPI) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
	}); err != nil {
		log.Printf("[LOCAL-API] Failed to encode health response: %v", err)
	}
}
