package ipc

import (
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

func TestDeviceDataReportRoundTrip(t *testing.T) {
	collectedAt := time.Now().UTC()
	response, err := NewResponse("req-1", DeviceDataReport{
		DeviceID:    "device-1",
		Hostname:    "host-1",
		OS:          "Windows",
		CollectedAt: collectedAt,
		Checks: []DeviceDataCheck{{
			Name:        "Firewall",
			Status:      DeviceDataStatusCritical,
			Description: "Firewall is disabled",
			Details:     map[string]string{"Public Profile": "OFF"},
		}},
	})
	if err != nil {
		t.Fatalf("NewResponse returned error: %v", err)
	}
	var report DeviceDataReport
	if err := DecodeBody(response.Body, &report); err != nil {
		t.Fatalf("DecodeBody returned error: %v", err)
	}
	if report.DeviceID != "device-1" || len(report.Checks) != 1 || report.Checks[0].Status != DeviceDataStatusCritical {
		t.Fatalf("report = %+v", report)
	}
}

func TestAgentDashboardRoundTrip(t *testing.T) {
	reportedAt := time.Now().UTC()
	response, err := NewResponse("req-1", AgentDashboard{
		Connection: DashboardConnection{State: "connected", ServiceState: "running"},
		Status:     AgentStatus{ServiceState: "running", EnrollmentState: EnrollmentStateUnenrolled, ReportedAt: reportedAt},
		Enrollment: EnrollmentInfo{State: EnrollmentStateUnenrolled},
		DeviceData: DeviceDataReport{DeviceID: "device-1", Checks: []DeviceDataCheck{{
			Name:        "Firewall",
			Status:      DeviceDataStatusGood,
			Description: "All firewall profiles are active",
		}}},
		ReportedAt: reportedAt,
	})
	if err != nil {
		t.Fatalf("NewResponse returned error: %v", err)
	}
	var dashboard AgentDashboard
	if err := DecodeBody(response.Body, &dashboard); err != nil {
		t.Fatalf("DecodeBody returned error: %v", err)
	}
	if dashboard.Connection.State != "connected" || dashboard.Enrollment.State != EnrollmentStateUnenrolled || len(dashboard.DeviceData.Checks) != 1 {
		t.Fatalf("dashboard = %+v", dashboard)
	}
}
