package transport

import (
	"log"
	"net/http"
	"strings"
	"time"
)

// ─────────────────────────────────────────────
// OIDC UserInfo
// ─────────────────────────────────────────────

// handleOIDCUserInfo implements the standard OIDC UserInfo Endpoint.
// GET /auth/userinfo — requires Bearer access_token from the token endpoint.
func (s *Server) handleOIDCUserInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	authHeader := r.Header.Get("Authorization")
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		w.Header().Set("WWW-Authenticate", `Bearer realm="trustcloud"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}

	claims, err := s.pa.Auth.ValidateToken(parts[1])
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="trustcloud", error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}

	// Look up full user record for email
	email := ""
	if user, ok := s.pa.Store.GetUser(claims.UserID); ok {
		email = user.Email
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"sub":                claims.Subject,
		"user_id":            claims.UserID,
		"preferred_username": claims.Username,
		"email":              email,
		"role":               claims.Role,
	})
}

// ─────────────────────────────────────────────
// Token Revocation
// ─────────────────────────────────────────────

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// Re-parse the caller's own token to get JTI and expiry
	authHeader := r.Header.Get("Authorization")
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing token"})
		return
	}

	claims, err := s.pa.Auth.ValidateToken(parts[1])
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}

	if claims.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token has no JTI"})
		return
	}

	expiresAt := time.Now().Add(s.pa.Cfg.JWTExpiry)
	if claims.ExpiresAt != nil {
		expiresAt = claims.ExpiresAt.Time
	}

	s.pa.Store.RevokeToken(claims.ID, expiresAt)

	log.Printf("[AUTH] Token revoked: jti=%s user=%s", claims.ID, claims.Username)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
