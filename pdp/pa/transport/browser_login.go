package transport

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
)

func (s *Server) handleWebLoginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	csrfToken := generateCSRFToken()
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Path:     "/",
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   s.appConfig().Runtime.CSRFCookieMaxAgeSeconds,
	})
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	s.serveDashboardIndex(w, r)
}

func generateCSRFToken() string {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return ""
	}
	return hex.EncodeToString(data)
}

func validateCSRF(r *http.Request) bool {
	cookie, err := r.Cookie("csrf_token")
	if err != nil || cookie.Value == "" {
		return false
	}
	headerToken := r.Header.Get("X-CSRF-Token")
	if headerToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(headerToken)) == 1
}
