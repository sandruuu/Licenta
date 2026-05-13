package store

import (
	"fmt"
	"log"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// ─────────────────────────────────────────────
// Token Revocation
// ─────────────────────────────────────────────

// RevokeToken adds a JTI to the revocation blacklist
func (s *Store) RevokeToken(jti string, expiresAt time.Time) {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO revoked_tokens (jti, revoked_at, expires_at) VALUES (?, ?, ?)`,
		jti, fmtTime(time.Now()), fmtTime(expiresAt))
	if err != nil {
		log.Printf("[STORE] Failed to revoke token %s: %v", jti, err)
	}
}

// ConsumeTokenOnce records a one-time token JTI and returns false when the JTI
// has already been consumed or revoked. The primary key makes this atomic for
// concurrent EST enrollment attempts using the same bearer token.
func (s *Store) ConsumeTokenOnce(jti string, expiresAt time.Time) bool {
	jti = strings.TrimSpace(jti)
	if jti == "" {
		return false
	}
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(5 * time.Minute)
	}
	_, err := s.db.Exec(`INSERT INTO revoked_tokens (jti, revoked_at, expires_at) VALUES (?, ?, ?)`,
		jti, fmtTime(time.Now()), fmtTime(expiresAt))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "constraint") || strings.Contains(strings.ToLower(err.Error()), "unique") {
			return false
		}
		log.Printf("[STORE] Failed to consume token %s: %v", jti, err)
		return false
	}
	return true
}

// IsTokenRevoked checks if a JTI has been revoked
func (s *Store) IsTokenRevoked(jti string) bool {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM revoked_tokens WHERE jti = ?", jti).Scan(&count)
	if err != nil {
		return false
	}
	return count > 0
}

// CleanExpiredRevokedTokens removes revoked tokens that have passed their original expiry
func (s *Store) CleanExpiredRevokedTokens() {
	result, err := s.db.Exec("DELETE FROM revoked_tokens WHERE expires_at < ?", fmtTime(time.Now()))
	if err != nil {
		log.Printf("[STORE] Failed to clean expired revoked tokens: %v", err)
		return
	}
	if n, _ := result.RowsAffected(); n > 0 {
		log.Printf("[STORE] Cleaned %d expired revoked tokens", n)
	}
}

// ─────────────────────────────────────────────
// Rate Limiting (persistent, SQLite-backed)
// ─────────────────────────────────────────────

const defaultEnrollRateLimitWindow = time.Minute
const defaultEnrollRateLimitMax = 5

// CheckEnrollRateLimit returns true if the IP is within the rate limit for
// the current window. The limit is persisted in SQLite so it survives PDP
// restarts and is shared across processes that use the same database.
func (s *Store) CheckEnrollRateLimit(ip string, window time.Duration, maxRequests int) (bool, error) {
	if ip == "" {
		return false, fmt.Errorf("ip is required")
	}
	if s.db == nil {
		return false, fmt.Errorf("database not initialized")
	}
	if window <= 0 {
		window = defaultEnrollRateLimitWindow
	}
	if maxRequests <= 0 {
		maxRequests = defaultEnrollRateLimitMax
	}

	now := time.Now().UTC()
	windowStart := now.Truncate(window)

	// Increment the count for this (ip, window) atomically.
	_, err := s.db.Exec(`INSERT INTO rate_limits (ip, window_start, request_count)
		VALUES (?, ?, 1)
		ON CONFLICT(ip, window_start) DO UPDATE SET request_count = request_count + 1`,
		ip, fmtTime(windowStart))
	if err != nil {
		log.Printf("[STORE] Rate limit check failed for IP %s: %v", ip, err)
		return false, err
	}

	var count int
	err = s.db.QueryRow("SELECT request_count FROM rate_limits WHERE ip = ? AND window_start = ?",
		ip, fmtTime(windowStart)).Scan(&count)
	if err != nil {
		return false, err
	}

	return count <= maxRequests, nil
}

// CleanExpiredRateLimits removes rate limit entries older than the given
// age. Call this periodically (e.g., every 5 minutes) to keep the table small.
func (s *Store) CleanExpiredRateLimits(maxAge time.Duration) {
	if s.db == nil {
		return
	}
	cutoff := fmtTime(time.Now().UTC().Add(-maxAge))
	result, err := s.db.Exec("DELETE FROM rate_limits WHERE window_start < ?", cutoff)
	if err != nil {
		log.Printf("[STORE] Failed to clean expired rate limits: %v", err)
		return
	}
	if n, _ := result.RowsAffected(); n > 0 {
		log.Printf("[STORE] Cleaned %d expired rate limit entries", n)
	}
}
