package deviceposture

import (
	"context"
	"testing"
	"time"

	"licenta/features/contracts"
)

func TestRunCheckTimeoutReturnsUnavailable(t *testing.T) {
	check, _ := runCheck(context.Background(), time.Nanosecond, "Slow Check", func(ctx context.Context) (contracts.DevicePostureCheck, string) {
		<-ctx.Done()
		return contracts.DevicePostureCheck{Name: "Slow Check", Status: contracts.DevicePostureStatusGood}, ""
	})
	if check.Name != "Slow Check" {
		t.Fatalf("check name = %q, want Slow Check", check.Name)
	}
	if check.Status != contracts.DevicePostureStatusUnavailable {
		t.Fatalf("check status = %q, want unavailable", check.Status)
	}
	if check.Details["timeout"] == "" {
		t.Fatalf("expected timeout detail")
	}
}

func TestCollectorReturnsRawChecksWithoutScore(t *testing.T) {
	collector := &Collector{CollectorBudget: time.Second, Now: func() time.Time { return time.Unix(1000, 0).UTC() }}
	report, err := collector.Collect(context.Background(), "device-1")
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if report.DeviceID != "device-1" || report.CollectedAt != time.Unix(1000, 0).UTC() {
		t.Fatalf("report = %+v", report)
	}
	if len(report.Checks) == 0 {
		t.Fatalf("expected at least one posture check")
	}
}

func TestParseKeyValueOutput(t *testing.T) {
	values := parseKeyValueOutput([]byte("Caption      : Microsoft Windows 11 Pro\r\nBuildNumber  : 22631\r\nIgnored\r\n"))
	if values["Caption"] != "Microsoft Windows 11 Pro" || values["BuildNumber"] != "22631" {
		t.Fatalf("values = %#v", values)
	}
	if _, ok := values["Ignored"]; ok {
		t.Fatalf("unexpected key from malformed line: %#v", values)
	}
}

func TestParseHexSeconds(t *testing.T) {
	if got := parseHexSeconds("0x0000012c"); got != "5 minutes" {
		t.Fatalf("parseHexSeconds() = %q, want 5 minutes", got)
	}
}
