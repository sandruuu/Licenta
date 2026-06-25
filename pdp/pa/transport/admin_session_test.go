package transport

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"pdp/models"
)

func TestAdminSessionRequiresRedisBackedSession(t *testing.T) {
	server, dataStore := newDeviceAPITestServer(t)
	user := saveAdminSessionTestUser(dataStore, "usr_admin_session_required", "admin-required@example.test")

	tokenWithoutSession, err := server.pa.Auth.JWT.GenerateAuthToken(user.ID, user.Username, user.Role, "", "", true)
	if err != nil {
		t.Fatalf("GenerateAuthToken() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/session", nil)
	req.Header.Set("Authorization", "Bearer "+tokenWithoutSession)
	rr := httptest.NewRecorder()
	server.adminAuthMiddleware(http.HandlerFunc(server.handleAdminSession)).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%s, want %d", rr.Code, rr.Body.String(), http.StatusUnauthorized)
	}
}

func TestAdminSessionRefreshRotatesRefreshToken(t *testing.T) {
	server, dataStore := newDeviceAPITestServer(t)
	user := saveAdminSessionTestUser(dataStore, "usr_admin_session_refresh", "admin-refresh@example.test")

	loginResponse, err := server.startAdminSession(user, "Authentication successful")
	if err != nil {
		t.Fatalf("startAdminSession() error = %v", err)
	}
	if loginResponse.SessionID == "" || loginResponse.RefreshToken == "" || loginResponse.AuthToken == "" {
		t.Fatalf("login response missing session fields: %+v", loginResponse)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/session", nil)
	req.Header.Set("Authorization", "Bearer "+loginResponse.AuthToken)
	rr := httptest.NewRecorder()
	server.adminAuthMiddleware(http.HandlerFunc(server.handleAdminSession)).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("session status = %d body=%s, want %d", rr.Code, rr.Body.String(), http.StatusOK)
	}

	refreshResponse, nextRefreshToken := refreshAdminSessionForTest(t, server, loginResponse.SessionID, loginResponse.RefreshToken)
	if refreshResponse.RefreshToken != "" || refreshResponse.SessionID != "" || refreshResponse.RefreshExpiresAt != "" {
		t.Fatalf("refresh response leaked cookie-backed session fields: %+v", refreshResponse)
	}
	if nextRefreshToken == "" || nextRefreshToken == loginResponse.RefreshToken {
		t.Fatalf("refresh token cookie was not rotated: before=%q after=%q", loginResponse.RefreshToken, nextRefreshToken)
	}

	reuseReq := httptest.NewRequest(http.MethodPost, "/api/auth/session/refresh", nil)
	addAdminSessionCookies(reuseReq, loginResponse.SessionID, loginResponse.RefreshToken)
	reuseRR := httptest.NewRecorder()
	server.handleAdminSessionRefresh(reuseRR, reuseReq)
	if reuseRR.Code != http.StatusUnauthorized {
		t.Fatalf("old refresh status = %d body=%s, want %d", reuseRR.Code, reuseRR.Body.String(), http.StatusUnauthorized)
	}
}

func TestAdminSessionRejectsPasswordChangeRequiredUser(t *testing.T) {
	server, dataStore := newDeviceAPITestServer(t)
	user := saveAdminSessionTestUser(dataStore, "usr_admin_session_password_change", "admin-change-required@example.test")

	loginResponse, err := server.startAdminSession(user, "Authentication successful")
	if err != nil {
		t.Fatalf("startAdminSession() error = %v", err)
	}

	user.PasswordChangeRequired = true
	user.UpdatedAt = time.Now().UTC()
	dataStore.SaveUser(user)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/session", nil)
	req.Header.Set("Authorization", "Bearer "+loginResponse.AuthToken)
	rr := httptest.NewRecorder()
	server.adminAuthMiddleware(http.HandlerFunc(server.handleAdminSession)).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s, want %d", rr.Code, rr.Body.String(), http.StatusForbidden)
	}
	if _, ok := server.adminSessions.load(loginResponse.SessionID); ok {
		t.Fatalf("admin session was not revoked after password change requirement")
	}
}

func TestAdminSessionAccessExtendsIdleTimeout(t *testing.T) {
	server, dataStore := newDeviceAPITestServer(t)
	user := saveAdminSessionTestUser(dataStore, "usr_admin_session_activity", "admin-activity@example.test")

	loginResponse, err := server.startAdminSession(user, "Authentication successful")
	if err != nil {
		t.Fatalf("startAdminSession() error = %v", err)
	}

	session, ok := server.adminSessions.load(loginResponse.SessionID)
	if !ok {
		t.Fatalf("admin session was not stored")
	}
	now := time.Now().UTC()
	initialIdleExpiry := now.Add(time.Minute)
	session.LastActivity = now.Add(-time.Minute)
	session.IdleExpiresAt = initialIdleExpiry
	session.AbsoluteExpiresAt = now.Add(time.Hour)
	if err := server.adminSessions.save(session); err != nil {
		t.Fatalf("save adjusted session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/session", nil)
	req.Header.Set("Authorization", "Bearer "+loginResponse.AuthToken)
	rr := httptest.NewRecorder()
	server.adminAuthMiddleware(http.HandlerFunc(server.handleAdminSession)).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("session status = %d body=%s, want %d", rr.Code, rr.Body.String(), http.StatusOK)
	}

	updated, ok := server.adminSessions.load(loginResponse.SessionID)
	if !ok {
		t.Fatalf("admin session disappeared after access")
	}
	if !updated.LastActivity.After(session.LastActivity) {
		t.Fatalf("last activity was not updated: before=%s after=%s", session.LastActivity, updated.LastActivity)
	}
	if !updated.IdleExpiresAt.After(initialIdleExpiry) {
		t.Fatalf("idle expiry was not extended: before=%s after=%s", initialIdleExpiry, updated.IdleExpiresAt)
	}
}

func TestAdminLogoutRevokesRedisSessionImmediately(t *testing.T) {
	server, dataStore := newDeviceAPITestServer(t)
	user := saveAdminSessionTestUser(dataStore, "usr_admin_session_logout", "admin-logout@example.test")

	loginResponse, err := server.startAdminSession(user, "Authentication successful")
	if err != nil {
		t.Fatalf("startAdminSession() error = %v", err)
	}
	logoutReq := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	logoutReq.Header.Set("Authorization", "Bearer "+loginResponse.AuthToken)
	addAdminSessionCookies(logoutReq, loginResponse.SessionID, loginResponse.RefreshToken)
	logoutRR := httptest.NewRecorder()
	server.handleAdminLogout(logoutRR, logoutReq)
	if logoutRR.Code != http.StatusOK {
		t.Fatalf("logout status = %d body=%s, want %d", logoutRR.Code, logoutRR.Body.String(), http.StatusOK)
	}
	assertAdminSessionCookieCleared(t, logoutRR, adminRefreshCookieName)
	assertAdminSessionCookieCleared(t, logoutRR, adminSessionCookieName)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/session", nil)
	req.Header.Set("Authorization", "Bearer "+loginResponse.AuthToken)
	rr := httptest.NewRecorder()
	server.adminAuthMiddleware(http.HandlerFunc(server.handleAdminSession)).ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("post-logout session status = %d body=%s, want %d", rr.Code, rr.Body.String(), http.StatusUnauthorized)
	}
}

func TestAdminSessionRefreshRejectsDisabledUser(t *testing.T) {
	server, dataStore := newDeviceAPITestServer(t)
	user := saveAdminSessionTestUser(dataStore, "usr_admin_session_disabled", "admin-disabled@example.test")

	loginResponse, err := server.startAdminSession(user, "Authentication successful")
	if err != nil {
		t.Fatalf("startAdminSession() error = %v", err)
	}

	user.Disabled = true
	user.UpdatedAt = time.Now().UTC()
	dataStore.SaveUser(user)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/session/refresh", nil)
	addAdminSessionCookies(req, loginResponse.SessionID, loginResponse.RefreshToken)
	rr := httptest.NewRecorder()
	server.handleAdminSessionRefresh(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%s, want %d", rr.Code, rr.Body.String(), http.StatusUnauthorized)
	}
}

func refreshAdminSessionForTest(t *testing.T, server *Server, sessionID, refreshToken string) (models.LoginResponse, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/session/refresh", nil)
	addAdminSessionCookies(req, sessionID, refreshToken)
	rr := httptest.NewRecorder()
	server.handleAdminSessionRefresh(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("refresh status = %d body=%s, want %d", rr.Code, rr.Body.String(), http.StatusOK)
	}
	nextRefreshToken := assertAdminSessionCookieSet(t, rr, adminRefreshCookieName)
	nextSessionID := assertAdminSessionCookieSet(t, rr, adminSessionCookieName)
	if nextSessionID != sessionID {
		t.Fatalf("session cookie changed: got %q want %q", nextSessionID, sessionID)
	}
	var response models.LoginResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("decode refresh response: %v", err)
	}
	return response, nextRefreshToken
}

func addAdminSessionCookies(req *http.Request, sessionID, refreshToken string) {
	req.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: sessionID})
	req.AddCookie(&http.Cookie{Name: adminRefreshCookieName, Value: refreshToken})
}

func assertAdminSessionCookieSet(t *testing.T, rr *httptest.ResponseRecorder, name string) string {
	t.Helper()
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name != name {
			continue
		}
		if cookie.Value == "" {
			t.Fatalf("cookie %s is empty", name)
		}
		if !cookie.HttpOnly {
			t.Fatalf("cookie %s is not HttpOnly", name)
		}
		if !cookie.Secure {
			t.Fatalf("cookie %s is not Secure", name)
		}
		if cookie.SameSite != http.SameSiteStrictMode {
			t.Fatalf("cookie %s SameSite = %v, want Strict", name, cookie.SameSite)
		}
		if cookie.Path != adminSessionCookiePath {
			t.Fatalf("cookie %s path = %q, want %q", name, cookie.Path, adminSessionCookiePath)
		}
		return cookie.Value
	}
	t.Fatalf("cookie %s was not set", name)
	return ""
}

func assertAdminSessionCookieCleared(t *testing.T, rr *httptest.ResponseRecorder, name string) {
	t.Helper()
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name != name {
			continue
		}
		if cookie.MaxAge >= 0 {
			t.Fatalf("cookie %s MaxAge = %d, want negative delete cookie", name, cookie.MaxAge)
		}
		if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
			t.Fatalf("cookie %s clear attributes are not hardened: %+v", name, cookie)
		}
		return
	}
	t.Fatalf("delete cookie %s was not set", name)
}

func saveAdminSessionTestUser(dataStore interface {
	SaveUser(*models.User)
}, id, email string) *models.User {
	now := time.Now().UTC()
	user := &models.User{
		ID:        id,
		Username:  email,
		Email:     email,
		Role:      "platform_admin",
		CreatedAt: now,
		UpdatedAt: now,
	}
	dataStore.SaveUser(user)
	return user
}
