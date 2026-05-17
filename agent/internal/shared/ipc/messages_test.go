package ipc

import (
	"strings"
	"testing"
	"time"
)

func TestPingRequestRoundTrip(t *testing.T) {
	request, err := NewRequest("req-1", OperationPing, PingRequest{Message: "hello", TrayPID: 10, SentAt: time.Now().UTC()})
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}
	var ping PingRequest
	if err := DecodeBody(request.Body, &ping); err != nil {
		t.Fatalf("DecodeBody returned error: %v", err)
	}
	if ping.Message != "hello" || ping.TrayPID != 10 {
		t.Fatalf("ping = %+v", ping)
	}
}

func TestStartEnrollmentRequestRoundTrip(t *testing.T) {
	sentAt := time.Now().UTC()
	expiresAt := sentAt.Add(time.Hour)
	request, err := NewRequest("req-1", OperationStartEnrollment, StartEnrollmentRequest{
		AccessToken:          "header.payload.signature",
		AccessTokenExpiresAt: expiresAt,
		Nonce:                "nonce-1",
		DeviceID:             "device-1",
		UserSID:              "S-1-5-21-1",
		KeyName:              "ZTNA_DeviceKey",
		UserEmail:            "alice@example.com",
		SentAt:               sentAt,
	})
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}
	var payload StartEnrollmentRequest
	if err := DecodeBody(request.Body, &payload); err != nil {
		t.Fatalf("DecodeBody returned error: %v", err)
	}
	if payload.AccessToken == "" || payload.Nonce != "nonce-1" || payload.KeyName != "ZTNA_DeviceKey" || !payload.AccessTokenExpiresAt.Equal(expiresAt) {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestUpdateAccessTokenRequestRoundTrip(t *testing.T) {
	expiresAt := time.Now().UTC().Add(time.Hour)
	request, err := NewRequest("req-1", OperationUpdateAccessToken, UpdateAccessTokenRequest{
		AccessToken: "header.payload.signature",
		ExpiresAt:   expiresAt,
		DeviceID:    "device-1",
		UserSID:     "S-1-5-21-1",
		SentAt:      time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}
	var payload UpdateAccessTokenRequest
	if err := DecodeBody(request.Body, &payload); err != nil {
		t.Fatalf("DecodeBody returned error: %v", err)
	}
	if payload.AccessToken != "header.payload.signature" || payload.DeviceID != "device-1" || !payload.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestDevicePostureReportRoundTrip(t *testing.T) {
	collectedAt := time.Now().UTC()
	request, err := NewRequest("req-1", OperationGetDevicePosture, DevicePostureRequest{})
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}
	if request.Operation != OperationGetDevicePosture {
		t.Fatalf("operation = %q", request.Operation)
	}
	response, err := NewResponse("req-1", DevicePostureReport{
		DeviceID:    "device-1",
		Hostname:    "host-1",
		OS:          "Windows",
		CollectedAt: collectedAt,
		Checks: []DevicePostureCheck{{
			Name:        "Firewall",
			Status:      DevicePostureStatusCritical,
			Description: "Firewall is disabled",
			Details:     map[string]string{"Public Profile": "OFF"},
		}},
	})
	if err != nil {
		t.Fatalf("NewResponse returned error: %v", err)
	}
	var report DevicePostureReport
	if err := DecodeBody(response.Body, &report); err != nil {
		t.Fatalf("DecodeBody returned error: %v", err)
	}
	if report.DeviceID != "device-1" || len(report.Checks) != 1 || report.Checks[0].Status != DevicePostureStatusCritical {
		t.Fatalf("report = %+v", report)
	}
}

func TestAgentDashboardRoundTrip(t *testing.T) {
	reportedAt := time.Now().UTC()
	response, err := NewResponse("req-1", AgentDashboard{
		Connection:  DashboardConnection{State: "connected", ServiceState: "running"},
		Status:      AgentStatus{ServiceState: "running", EnrollmentState: EnrollmentStateEnrolled, ReportedAt: reportedAt},
		Enrollment:  EnrollmentInfo{State: EnrollmentStateEnrolled, DeviceID: "device-1", KeyExists: true},
		Certificate: CertificateInfo{SHA256: "abc", ExpiresAt: reportedAt.Add(time.Hour), Valid: true},
		User:        AuthenticatedUser{UserSID: "S-1-5-21-1", Email: "alice@example.com", SessionState: "ready"},
		Posture: DevicePostureReport{DeviceID: "device-1", Checks: []DevicePostureCheck{{
			Name:        "Firewall",
			Status:      DevicePostureStatusGood,
			Description: "All firewall profiles are active",
		}}},
		Resources:      []CatalogResource{{FQDN: "admin.example.test", ResourceID: "res-1", Protocol: "tcp", Port: 443, Status: "available"}},
		ActiveSessions: []ActiveSession{{ID: "sess-1", FQDN: "admin.example.test", State: "active"}},
		AccessEvents:   []AccessEvent{{ID: "evt-1", Decision: "deny", Reason: "token required", OccurredAt: reportedAt}},
		ReportedAt:     reportedAt,
	})
	if err != nil {
		t.Fatalf("NewResponse returned error: %v", err)
	}
	var dashboard AgentDashboard
	if err := DecodeBody(response.Body, &dashboard); err != nil {
		t.Fatalf("DecodeBody returned error: %v", err)
	}
	if dashboard.Connection.State != "connected" || len(dashboard.Resources) != 1 || len(dashboard.AccessEvents) != 1 {
		t.Fatalf("dashboard = %+v", dashboard)
	}
}

func TestPipeSecurityDescriptorAllowsInteractiveUsersByDefault(t *testing.T) {
	descriptor, err := PipeSecurityDescriptor("")
	if err != nil {
		t.Fatalf("PipeSecurityDescriptor returned error: %v", err)
	}
	for _, required := range []string{"SY", "BA", "IU"} {
		if !strings.Contains(descriptor, required) {
			t.Fatalf("descriptor %q does not contain %q", descriptor, required)
		}
	}
	for _, forbidden := range []string{"WD", "AN", "AU"} {
		if strings.Contains(descriptor, forbidden) {
			t.Fatalf("descriptor %q contains broad SID %q", descriptor, forbidden)
		}
	}
}

func TestPipeSecurityDescriptorAddsAuthorizedUserSID(t *testing.T) {
	userSID := "S-1-5-21-1000-2000-3000-1001"
	descriptor, err := PipeSecurityDescriptor(userSID)
	if err != nil {
		t.Fatalf("PipeSecurityDescriptor returned error: %v", err)
	}
	if !strings.Contains(descriptor, userSID) {
		t.Fatalf("descriptor %q does not contain authorized SID", descriptor)
	}
	if _, err := PipeSecurityDescriptor("Everyone"); err == nil {
		t.Fatalf("PipeSecurityDescriptor accepted invalid SID")
	}
}
