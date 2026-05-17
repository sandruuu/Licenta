package controlplane

import (
	"fmt"
	"log"
	"sync"
	"time"
)

type CircuitState int

const (
	CircuitClosed CircuitState = iota
	CircuitOpen
	CircuitHalfOpen
)

func (state CircuitState) String() string {
	switch state {
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

type CircuitBreaker struct {
	mu sync.Mutex

	state       CircuitState
	failures    int
	lastFailure time.Time
	lastSuccess time.Time

	maxFailures        int
	timeout            time.Duration
	halfOpenMaxLatency time.Duration

	totalTrips           int64
	totalSuccess         int64
	totalFailure         int64
	totalHalfOpenTimeout int64
}

type CircuitBreakerConfig struct {
	MaxFailures        int
	OpenTimeout        time.Duration
	HalfOpenMaxLatency time.Duration
}

func NewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
	return &CircuitBreaker{
		state:              CircuitClosed,
		maxFailures:        config.MaxFailures,
		timeout:            config.OpenTimeout,
		halfOpenMaxLatency: config.HalfOpenMaxLatency,
	}
}

func (breaker *CircuitBreaker) Execute(fn func() ([]byte, error)) ([]byte, error) {
	breaker.mu.Lock()

	probing := false
	switch breaker.state {
	case CircuitOpen:
		if time.Since(breaker.lastFailure) > breaker.timeout {
			log.Printf("[PA] circuit breaker: open -> half-open")
			breaker.state = CircuitHalfOpen
			breaker.failures = 0
			probing = true
			breaker.mu.Unlock()
		} else {
			breaker.mu.Unlock()
			return nil, ErrCircuitOpen
		}
	case CircuitHalfOpen:
		probing = true
		breaker.mu.Unlock()
	case CircuitClosed:
		breaker.mu.Unlock()
	}

	var (
		result []byte
		err    error
	)

	breaker.mu.Lock()
	probeBudget := breaker.halfOpenMaxLatency
	breaker.mu.Unlock()

	if probing && probeBudget > 0 {
		type probeResult struct {
			data []byte
			err  error
		}
		resultCh := make(chan probeResult, 1)
		go func() {
			data, probeErr := fn()
			resultCh <- probeResult{data: data, err: probeErr}
		}()
		select {
		case probe := <-resultCh:
			result, err = probe.data, probe.err
		case <-time.After(probeBudget):
			breaker.mu.Lock()
			breaker.totalHalfOpenTimeout++
			breaker.totalFailure++
			breaker.totalTrips++
			breaker.failures = 0
			breaker.lastFailure = time.Now()
			breaker.state = CircuitOpen
			log.Printf("[PA] circuit breaker: half-open -> open (probe exceeded %s)", probeBudget)
			breaker.mu.Unlock()
			return nil, fmt.Errorf("circuit breaker: half-open probe exceeded %s", probeBudget)
		}
	} else {
		result, err = fn()
	}

	breaker.mu.Lock()
	defer breaker.mu.Unlock()

	if err != nil {
		breaker.failures++
		breaker.totalFailure++
		breaker.lastFailure = time.Now()
		if breaker.state == CircuitHalfOpen {
			log.Printf("[PA] circuit breaker: half-open -> open")
			breaker.state = CircuitOpen
			breaker.totalTrips++
		} else if breaker.failures >= breaker.maxFailures {
			log.Printf("[PA] circuit breaker: closed -> open (%d consecutive failures)", breaker.failures)
			breaker.state = CircuitOpen
			breaker.totalTrips++
		}
		return nil, err
	}

	breaker.totalSuccess++
	breaker.lastSuccess = time.Now()
	if breaker.state != CircuitClosed {
		log.Printf("[PA] circuit breaker: %s -> closed", breaker.state)
	}
	breaker.failures = 0
	breaker.state = CircuitClosed
	return result, nil
}

func (breaker *CircuitBreaker) State() CircuitState {
	breaker.mu.Lock()
	defer breaker.mu.Unlock()
	return breaker.state
}

func (breaker *CircuitBreaker) Metrics() (trips, successes, failures int64) {
	breaker.mu.Lock()
	defer breaker.mu.Unlock()
	return breaker.totalTrips, breaker.totalSuccess, breaker.totalFailure
}

func (breaker *CircuitBreaker) HalfOpenTimeouts() int64 {
	breaker.mu.Lock()
	defer breaker.mu.Unlock()
	return breaker.totalHalfOpenTimeout
}

var ErrCircuitOpen = fmt.Errorf("circuit breaker is open: PA service unavailable")
