package deviceposture

import (
	"context"
	"testing"
	"time"

	"ztna.local/agent/internal/ipc"
)

func TestRunCheckTimeoutReturnsUnavailable(t *testing.T) {
	check, _ := runCheck(context.Background(), time.Nanosecond, "Slow Check", func(ctx context.Context) (ipc.DevicePostureCheck, string) {
		<-ctx.Done()
		return ipc.DevicePostureCheck{Name: "Slow Check", Status: ipc.DevicePostureStatusGood}, ""
	})
	if check.Name != "Slow Check" {
		t.Fatalf("check name = %q, want Slow Check", check.Name)
	}
	if check.Status != ipc.DevicePostureStatusUnavailable {
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
