package auth

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// CircuitState represents the state of the circuit breaker
type CircuitState int

const (
	CircuitClosed   CircuitState = iota // normal operation
	CircuitOpen                         // failing, reject fast
	CircuitHalfOpen                     // testing recovery
)

func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreaker implements the circuit breaker pattern for cloud API calls.
// When the cloud is unreachable, the breaker opens to fail fast and allow
// the gateway to degrade gracefully using cached data.
type CircuitBreaker struct {
	mu sync.Mutex

	state       CircuitState
	failures    int       // consecutive failures in closed state
	lastFailure time.Time // timestamp of last failure
	lastSuccess time.Time // timestamp of last success

	// Configuration
	maxFailures        int           // failures before opening (default: 5)
	timeout            time.Duration // how long to stay open before half-open (default: 30s)
	halfOpenMax        int           // max probe requests in half-open (default: 1)
	halfOpenMaxLatency time.Duration // max duration of a half-open probe (default: 2s)

	// Metrics
	totalTrips           int64 // number of times breaker opened
	totalSuccess         int64
	totalFailure         int64
	totalHalfOpenTimeout int64 // half-open probes that exceeded halfOpenMaxLatency
}

// NewCircuitBreaker creates a circuit breaker with sensible defaults.
func NewCircuitBreaker() *CircuitBreaker {
	return &CircuitBreaker{
		state:              CircuitClosed,
		maxFailures:        5,
		timeout:            30 * time.Second,
		halfOpenMax:        1,
		halfOpenMaxLatency: 2 * time.Second,
	}
}

// SetHalfOpenMaxLatency overrides the maximum duration a half-open probe
// is allowed to run before being treated as a failure. A value <= 0 disables
// the timeout (probe waits for the underlying client timeout).
func (cb *CircuitBreaker) SetHalfOpenMaxLatency(d time.Duration) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.halfOpenMaxLatency = d
}

// Execute runs the given function through the circuit breaker.
// If the circuit is open, it returns ErrCircuitOpen immediately.
// If the circuit is half-open, it allows a single probe request bounded by
// halfOpenMaxLatency — a probe that exceeds this duration is treated as a
// failure and re-opens the circuit, preventing a slow cloud from stalling
// the gateway via half-open probes.
func (cb *CircuitBreaker) Execute(fn func() ([]byte, error)) ([]byte, error) {
	cb.mu.Lock()

	probing := false

	switch cb.state {
	case CircuitOpen:
		// Check if timeout has elapsed → transition to half-open
		if time.Since(cb.lastFailure) > cb.timeout {
			log.Printf("[AUTH] Circuit breaker: open → half-open (timeout elapsed)")
			cb.state = CircuitHalfOpen
			cb.failures = 0
			probing = true
			cb.mu.Unlock()
			// Fall through to execute the probe
		} else {
			cb.mu.Unlock()
			return nil, ErrCircuitOpen
		}

	case CircuitHalfOpen:
		probing = true
		cb.mu.Unlock()

	case CircuitClosed:
		cb.mu.Unlock()
	}

	// Execute the actual call. In half-open mode, bound the probe latency so
	// a slow-but-not-dead cloud cannot keep the breaker stuck blocking other
	// callers. The orphan goroutine is bounded by the underlying HTTP client
	// timeout configured by the caller.
	var (
		result []byte
		err    error
	)

	cb.mu.Lock()
	probeBudget := cb.halfOpenMaxLatency
	cb.mu.Unlock()

	if probing && probeBudget > 0 {
		type probeResult struct {
			data []byte
			err  error
		}
		ch := make(chan probeResult, 1)
		go func() {
			d, e := fn()
			ch <- probeResult{d, e}
		}()
		select {
		case r := <-ch:
			result, err = r.data, r.err
		case <-time.After(probeBudget):
			cb.mu.Lock()
			cb.totalHalfOpenTimeout++
			cb.totalFailure++
			cb.totalTrips++
			cb.failures = 0
			cb.lastFailure = time.Now()
			cb.state = CircuitOpen
			log.Printf("[AUTH] Circuit breaker: half-open → open (probe exceeded %s)", probeBudget)
			cb.mu.Unlock()
			return nil, fmt.Errorf("circuit breaker: half-open probe exceeded %s", probeBudget)
		}
	} else {
		result, err = fn()
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		cb.failures++
		cb.totalFailure++
		cb.lastFailure = time.Now()

		if cb.state == CircuitHalfOpen {
			// Probe failed → back to open
			log.Printf("[AUTH] Circuit breaker: half-open → open (probe failed)")
			cb.state = CircuitOpen
			cb.totalTrips++
		} else if cb.failures >= cb.maxFailures {
			// Too many failures → open the circuit
			log.Printf("[AUTH] Circuit breaker: closed → open (%d consecutive failures)", cb.failures)
			cb.state = CircuitOpen
			cb.totalTrips++
		}
		return nil, err
	}

	// Success
	cb.totalSuccess++
	cb.lastSuccess = time.Now()
	if cb.state != CircuitClosed {
		log.Printf("[AUTH] Circuit breaker: %s → closed (success)", cb.state)
	}
	cb.failures = 0
	cb.state = CircuitClosed
	return result, nil
}

// State returns the current circuit breaker state.
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

// Metrics returns cumulative statistics about the circuit breaker.
func (cb *CircuitBreaker) Metrics() (trips, successes, failures int64) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.totalTrips, cb.totalSuccess, cb.totalFailure
}

// HalfOpenTimeouts returns the cumulative number of half-open probes that
// exceeded halfOpenMaxLatency and forced the circuit back to open.
func (cb *CircuitBreaker) HalfOpenTimeouts() int64 {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.totalHalfOpenTimeout
}

// ErrCircuitOpen is returned when the circuit breaker is open
// and calls are being rejected to protect the system.
var ErrCircuitOpen = fmt.Errorf("circuit breaker is open: cloud service unavailable")
