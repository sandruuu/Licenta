package transport

import (
	"log"
	"net/http"
	"strings"
	"time"
)

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	authHeader := r.Header.Get("Authorization")
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
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

	expiresAt := time.Now()
	if claims.ExpiresAt != nil {
		expiresAt = claims.ExpiresAt.Time
	}
	s.pa.Store.RevokeToken(claims.ID, expiresAt)

	log.Printf("[AUTH] Token revoked: jti=%s user=%s", claims.ID, claims.Username)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
