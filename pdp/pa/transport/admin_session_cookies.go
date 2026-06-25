package transport

import (
	"net/http"
	"strings"
	"time"

	"pdp/models"
)

const (
	adminRefreshCookieName = "trustcloud_admin_refresh"
	adminSessionCookieName = "trustcloud_admin_session"
	adminSessionCookiePath = "/api/auth"
)

func (s *Server) writeAdminSessionResponse(w http.ResponseWriter, status int, response *models.LoginResponse) {
	if response == nil {
		writeJSON(w, status, response)
		return
	}
	setAdminSessionCookies(w, response.SessionID, response.RefreshToken, response.RefreshExpiresAt)
	response.RefreshToken = ""
	response.SessionID = ""
	response.RefreshExpiresAt = ""
	writeJSON(w, status, response)
}

func setAdminSessionCookies(w http.ResponseWriter, sessionID, refreshToken, refreshExpiresAt string) {
	expires := parseCookieExpiry(refreshExpiresAt)
	if strings.TrimSpace(sessionID) != "" {
		http.SetCookie(w, adminSessionCookie(sessionID, expires, 0))
	}
	if strings.TrimSpace(refreshToken) != "" {
		http.SetCookie(w, adminRefreshCookie(refreshToken, expires, 0))
	}
}

func clearAdminSessionCookies(w http.ResponseWriter) {
	http.SetCookie(w, adminSessionCookie("", time.Time{}, -1))
	http.SetCookie(w, adminRefreshCookie("", time.Time{}, -1))
}

func adminSessionCredentialsFromCookies(r *http.Request) (string, string, bool) {
	if r == nil {
		return "", "", false
	}
	sessionCookie, sessionErr := r.Cookie(adminSessionCookieName)
	refreshCookie, refreshErr := r.Cookie(adminRefreshCookieName)
	if sessionErr != nil || refreshErr != nil {
		return "", "", false
	}
	sessionID := strings.TrimSpace(sessionCookie.Value)
	refreshToken := strings.TrimSpace(refreshCookie.Value)
	return sessionID, refreshToken, sessionID != "" && refreshToken != ""
}

func adminSessionCookie(value string, expires time.Time, maxAge int) *http.Cookie {
	return adminCookie(adminSessionCookieName, value, expires, maxAge)
}

func adminRefreshCookie(value string, expires time.Time, maxAge int) *http.Cookie {
	return adminCookie(adminRefreshCookieName, value, expires, maxAge)
}

func adminCookie(name, value string, expires time.Time, maxAge int) *http.Cookie {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     adminSessionCookiePath,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	}
	if !expires.IsZero() {
		cookie.Expires = expires.UTC()
	}
	return cookie
}

func parseCookieExpiry(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	expires, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return expires.UTC()
}
