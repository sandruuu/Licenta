package deviceposture

import (
	"testing"
	"time"

	"ztna.local/agent/internal/ipc"
)

func TestPostureReportStructDoesNotIncludeScore(t *testing.T) {
	report := ipc.DevicePostureReport{
		DeviceID:    "device-1",
		Hostname:    "host-1",
		OS:          "Windows",
		CollectedAt: time.Unix(1000, 0).UTC(),
		Checks: []ipc.DevicePostureCheck{{
			Name:        "Firewall",
			Status:      ipc.DevicePostureStatusCritical,
			Description: "disabled",
			Details:     map[string]string{"profile": "domain"},
		}},
	}
	message, err := postureReportStruct(report)
	if err != nil {
		t.Fatalf("postureReportStruct returned error: %v", err)
	}
	fields := message.GetFields()
	if _, ok := fields["overall_score"]; ok {
		t.Fatalf("gRPC posture payload included local score: %+v", fields)
	}
	if fields["device_id"].GetStringValue() != "device-1" || fields["hostname"].GetStringValue() != "host-1" {
		t.Fatalf("fields = %+v", fields)
	}
	checks := fields["checks"].GetListValue().GetValues()
	if len(checks) != 1 || checks[0].GetStructValue().GetFields()["status"].GetStringValue() != ipc.DevicePostureStatusCritical {
		t.Fatalf("checks = %+v", checks)
	}
}

func TestPostureReportStructOmitsZeroCollectedAt(t *testing.T) {
	message, err := postureReportStruct(ipc.DevicePostureReport{DeviceID: "device-1"})
	if err != nil {
		t.Fatalf("postureReportStruct returned error: %v", err)
	}
	if _, ok := message.GetFields()["collected_at"]; ok {
		t.Fatalf("gRPC posture payload included zero collected_at: %+v", message.GetFields())
	}
}

func TestGRPCTargetFromCloudURL(t *testing.T) {
	target, serverName, err := grpcTargetFromCloudURL("https://cloud.example:8443")
	if err != nil {
		t.Fatalf("grpcTargetFromCloudURL returned error: %v", err)
	}
	if target != "cloud.example:8443" || serverName != "cloud.example" {
		t.Fatalf("target=%q serverName=%q", target, serverName)
	}
}
