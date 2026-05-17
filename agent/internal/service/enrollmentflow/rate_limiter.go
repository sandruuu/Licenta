package enrollmentflow

import (
	"sync"
	"time"
)

type RateLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string][]time.Time
}

func NewRateLimiter(max int, window time.Duration) *RateLimiter {
	return &RateLimiter{max: max, window: window, hits: make(map[string][]time.Time)}
}

func (limiter *RateLimiter) Allow(key string, now time.Time) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	cutoff := now.Add(-limiter.window)
	recent := limiter.hits[key][:0]
	for _, hit := range limiter.hits[key] {
		if hit.After(cutoff) {
			recent = append(recent, hit)
		}
	}
	if len(recent) >= limiter.max {
		limiter.hits[key] = recent
		return false
	}
	recent = append(recent, now)
	limiter.hits[key] = recent
	return true
}
