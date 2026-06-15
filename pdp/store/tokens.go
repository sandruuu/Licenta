package store

import (
	"log"
	"strings"
	"time"
)

// RevokeToken adds a JTI to the revocation blacklist.
func (s *Store) RevokeToken(jti string, expiresAt time.Time) {
	_, err := s.db.Exec(`INSERT INTO revoked_tokens (jti, revoked_at, expires_at)
		VALUES (?, ?, ?)
		ON CONFLICT (jti) DO UPDATE SET
			revoked_at = EXCLUDED.revoked_at,
			expires_at = EXCLUDED.expires_at`,
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
	result, err := s.db.Exec(`INSERT INTO revoked_tokens (jti, revoked_at, expires_at)
		VALUES (?, ?, ?)
		ON CONFLICT (jti) DO NOTHING`,
		jti, fmtTime(time.Now()), fmtTime(expiresAt))
	if err != nil {
		log.Printf("[STORE] Failed to consume token %s: %v", jti, err)
		return false
	}
	affected, err := result.RowsAffected()
	return err == nil && affected == 1
}

// IsTokenRevoked checks if a JTI has been revoked.
func (s *Store) IsTokenRevoked(jti string) bool {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM revoked_tokens WHERE jti = ?", jti).Scan(&count)
	if err != nil {
		return false
	}
	return count > 0
}

// CleanExpiredRevokedTokens removes revoked tokens that passed their original expiry.
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
