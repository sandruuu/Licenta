package admin

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// secretsStatus returns metadata about gateway secrets (without exposing values)
type secretsStatus struct {
	OIDCSecret  secretInfo `json:"oidc_client_secret"`
	AdminTokens secretInfo `json:"admin_tokens"`
}

type secretInfo struct {
	Configured  bool   `json:"configured"`
	LastRotated string `json:"last_rotated,omitempty"`
	Hint        string `json:"hint,omitempty"` // last 4 chars
}

// handleSecretsStatus returns metadata about configured secrets.
// GET /api/secrets/status
func (s *Server) handleSecretsStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	status := secretsStatus{
		AdminTokens: secretInfo{
			Configured: len(s.adminTokens) > 0,
		},
	}
	if s.cfg.AuthSource != nil {
		status.OIDCSecret = secretInfo{
			Configured: s.cfg.AuthSource.ClientSecret != "",
			Hint:       lastN(s.cfg.AuthSource.ClientSecret, 4),
		}
	}

	writeJSON(w, http.StatusOK, status)
}

// handleSecretsRotate rotates the specified secret.
// POST /api/secrets/rotate
// Body: { "secret": "cloud_api_key" | "admin_tokens" }
func (s *Server) handleSecretsRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req struct {
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	switch req.Secret {
	case "admin_tokens":
		// Invalidate all admin session tokens (force re-login)
		s.mu.Lock()
		count := len(s.adminTokens)
		s.adminTokens = make(map[string]time.Time)
		s.tokenActivity = make(map[string]time.Time)
		s.mu.Unlock()

		log.Printf("[ADMIN] All admin tokens invalidated (%d sessions)", count)
		s.logInfo("secret.rotated", fmt.Sprintf("All admin tokens invalidated (%d sessions)", count), map[string]string{
			"secret": "admin_tokens",
			"admin":  s.cfg.Setup.AdminEmail,
		})

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":            "rotated",
			"secret":            "admin_tokens",
			"invalidated_count": count,
			"rotated":           time.Now().Format(time.RFC3339),
		})

	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":   "unknown secret type",
			"allowed": "admin_tokens",
		})
	}
}

// generateSecureToken generates a cryptographically random hex-encoded token
func generateSecureToken(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// lastN returns the last n characters of a string, or the full string if shorter
func lastN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
