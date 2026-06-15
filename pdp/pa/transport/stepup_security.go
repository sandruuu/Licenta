package transport

import (
	"crypto/subtle"
	"net/http"
	"net/url"
	"strings"
)

func setNoStoreHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

func (s *Server) ensureCSRFCookie(w http.ResponseWriter, r *http.Request) string {
	if cookie, err := r.Cookie("csrf_token"); err == nil && strings.TrimSpace(cookie.Value) != "" {
		return cookie.Value
	}
	token := generateCSRFToken()
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   s.appConfig().Runtime.CSRFCookieMaxAgeSeconds,
	})
	return token
}

func validateCSRFSubmission(r *http.Request) bool {
	cookie, err := r.Cookie("csrf_token")
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return false
	}
	token := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
	if token == "" {
		token = strings.TrimSpace(r.Form.Get("csrf_token"))
	}
	if token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(token)) == 1
}

func (s *Server) validateStepUpMutationOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" {
		return s.sameBrowserOrigin(r, origin)
	}
	referer := strings.TrimSpace(r.Header.Get("Referer"))
	if referer != "" {
		return s.sameBrowserOrigin(r, referer)
	}
	return true
}

func (s *Server) sameBrowserOrigin(r *http.Request, raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	requestScheme := "http"
	if r.TLS != nil {
		requestScheme = "https"
	}
	if strings.EqualFold(parsed.Scheme, requestScheme) && strings.EqualFold(parsed.Host, r.Host) {
		return true
	}
	publicOrigin := ""
	if s != nil {
		publicOrigin, _ = s.publicOrigin()
	}
	if publicOrigin == "" {
		return false
	}
	expected, err := url.Parse(publicOrigin)
	if err != nil || expected.Scheme == "" || expected.Host == "" {
		return false
	}
	return strings.EqualFold(parsed.Scheme, expected.Scheme) && strings.EqualFold(parsed.Host, expected.Host)
}
