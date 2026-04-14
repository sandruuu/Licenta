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
	maxFailures int           // failures before opening (default: 5)
	timeout     time.Duration // how long to stay open before half-open (default: 30s)
	halfOpenMax int           // max probe requests in half-open (default: 1)

	// Metrics
	totalTrips   int64 // number of times breaker opened
	totalSuccess int64
	totalFailure int64
}

// NewCircuitBreaker creates a circuit breaker with sensible defaults.
func NewCircuitBreaker() *CircuitBreaker {
	return &CircuitBreaker{
		state:       CircuitClosed,
		maxFailures: 5,
		timeout:     30 * time.Second,
		halfOpenMax: 1,
	}
}

// Execute runs the given function through the circuit breaker.
// If the circuit is open, it returns ErrCircuitOpen immediately.
// If the circuit is half-open, it allows a single probe request.
func (cb *CircuitBreaker) Execute(fn func() ([]byte, error)) ([]byte, error) {
	cb.mu.Lock()

	switch cb.state {
	case CircuitOpen:
		// Check if timeout has elapsed → transition to half-open
		if time.Since(cb.lastFailure) > cb.timeout {
			log.Printf("[AUTH] Circuit breaker: open → half-open (timeout elapsed)")
			cb.state = CircuitHalfOpen
			cb.failures = 0
			cb.mu.Unlock()
			// Fall through to execute the probe
		} else {
			cb.mu.Unlock()
			return nil, ErrCircuitOpen
		}

	case CircuitHalfOpen:
		// Allow limited probe requests
		cb.mu.Unlock()

	case CircuitClosed:
		cb.mu.Unlock()
	}

	// Execute the actual call
	result, err := fn()

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

// ErrCircuitOpen is returned when the circuit breaker is open
// and calls are being rejected to protect the system.
var ErrCircuitOpen = fmt.Errorf("circuit breaker is open: cloud service unavailable")
