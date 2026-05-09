package enrollment

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestEnrollmentTokenPostsDeviceNonceAndSID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/enroll/token" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer access-token" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("Decode body returned error: %v", err)
		}
		if body["device_id"] != "device-1" || body["nonce"] != "nonce-1" || body["user_sid"] != "S-1-5-21-1" {
			t.Fatalf("body = %+v", body)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"enrollment_token": "jwt.token.value",
			"token_type":       "Bearer",
			"expires_in":       300,
			"device_id":        "device-1",
			"nonce":            "nonce-1",
			"user_sid":         "S-1-5-21-1",
			"user_email":       "alice@example.com",
		})
	}))
	defer server.Close()
	client, err := NewClient(Config{CloudURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	token, err := client.RequestEnrollmentToken(context.Background(), TokenRequest{AccessToken: "access-token", DeviceID: "device-1", Nonce: "nonce-1", UserSID: "S-1-5-21-1"})
	if err != nil {
		t.Fatalf("RequestEnrollmentToken returned error: %v", err)
	}
	if token.EnrollmentToken == "" || token.UserEmail != "alice@example.com" || token.ExpiresIn != 300 {
		t.Fatalf("token = %+v", token)
	}
}

func TestRequestEnrollmentTokenRejectsDeviceMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"enrollment_token": "jwt.token.value",
			"token_type":       "Bearer",
			"expires_in":       300,
			"device_id":        "other-device",
			"nonce":            "nonce-1",
		})
	}))
	defer server.Close()
	client, err := NewClient(Config{CloudURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	if _, err := client.RequestEnrollmentToken(context.Background(), TokenRequest{AccessToken: "access-token", DeviceID: "device-1", Nonce: "nonce-1"}); err == nil {
		t.Fatalf("RequestEnrollmentToken accepted mismatched device_id")
	}
}
