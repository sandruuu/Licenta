package transport

import (
	"bytes"
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

	refreshResponse := refreshAdminSessionForTest(t, server, loginResponse.SessionID, loginResponse.RefreshToken)
	if refreshResponse.RefreshToken == "" || refreshResponse.RefreshToken == loginResponse.RefreshToken {
		t.Fatalf("refresh token was not rotated: before=%q after=%q", loginResponse.RefreshToken, refreshResponse.RefreshToken)
	}
	if refreshResponse.SessionID != loginResponse.SessionID {
		t.Fatalf("session id changed: got %q want %q", refreshResponse.SessionID, loginResponse.SessionID)
	}

	reuseBody := bytes.NewBufferString(`{"session_id":"` + loginResponse.SessionID + `","refresh_token":"` + loginResponse.RefreshToken + `"}`)
	reuseReq := httptest.NewRequest(http.MethodPost, "/api/auth/session/refresh", reuseBody)
	reuseRR := httptest.NewRecorder()
	server.handleAdminSessionRefresh(reuseRR, reuseReq)
	if reuseRR.Code != http.StatusUnauthorized {
		t.Fatalf("old refresh status = %d body=%s, want %d", reuseRR.Code, reuseRR.Body.String(), http.StatusUnauthorized)
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
	body := bytes.NewBufferString(`{"session_id":"` + loginResponse.SessionID + `","refresh_token":"` + loginResponse.RefreshToken + `"}`)
	logoutReq := httptest.NewRequest(http.MethodPost, "/api/auth/logout", body)
	logoutReq.Header.Set("Authorization", "Bearer "+loginResponse.AuthToken)
	logoutRR := httptest.NewRecorder()
	server.handleAdminLogout(logoutRR, logoutReq)
	if logoutRR.Code != http.StatusOK {
		t.Fatalf("logout status = %d body=%s, want %d", logoutRR.Code, logoutRR.Body.String(), http.StatusOK)
	}

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

	body := bytes.NewBufferString(`{"session_id":"` + loginResponse.SessionID + `","refresh_token":"` + loginResponse.RefreshToken + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/session/refresh", body)
	rr := httptest.NewRecorder()
	server.handleAdminSessionRefresh(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%s, want %d", rr.Code, rr.Body.String(), http.StatusUnauthorized)
	}
}

func refreshAdminSessionForTest(t *testing.T, server *Server, sessionID, refreshToken string) models.LoginResponse {
	t.Helper()
	body := bytes.NewBufferString(`{"session_id":"` + sessionID + `","refresh_token":"` + refreshToken + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/session/refresh", body)
	rr := httptest.NewRecorder()
	server.handleAdminSessionRefresh(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("refresh status = %d body=%s, want %d", rr.Code, rr.Body.String(), http.StatusOK)
	}
	var response models.LoginResponse
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("decode refresh response: %v", err)
	}
	return response
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
