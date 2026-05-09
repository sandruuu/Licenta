package health

import (
	"context"
	"testing"
	"time"

	"ztna.local/endpoint-agent/internal/ipc"
)

func TestCalculateScoreUsesWeightedChecks(t *testing.T) {
	checks := []ipc.HealthCheck{
		{Name: "Firewall", Status: "good"},
		{Name: "Antivirus", Status: "warning"},
		{Name: "Disk Encryption", Status: "critical"},
		{Name: "Password & Lock", Status: "warning"},
		{Name: "Operating System", Status: "good"},
	}
	if score := CalculateScore(checks); score != 60 {
		t.Fatalf("score = %d, want 60", score)
	}
}

func TestCalculateScoreFallsBackToAverageForUnknownChecks(t *testing.T) {
	checks := []ipc.HealthCheck{
		{Name: "Custom One", Status: "good"},
		{Name: "Custom Two", Status: "warning"},
		{Name: "Custom Three", Status: "critical"},
	}
	if score := CalculateScore(checks); score != 50 {
		t.Fatalf("score = %d, want 50", score)
	}
}

func TestRunCheckTimeoutReturnsWarning(t *testing.T) {
	check, _ := runCheck(context.Background(), time.Nanosecond, "Slow Check", func(ctx context.Context) (ipc.HealthCheck, string) {
		<-ctx.Done()
		return ipc.HealthCheck{Name: "Slow Check", Status: "good"}, ""
	})
	if check.Name != "Slow Check" {
		t.Fatalf("check name = %q, want Slow Check", check.Name)
	}
	if check.Status != "warning" {
		t.Fatalf("check status = %q, want warning", check.Status)
	}
	if check.Details["timeout"] == "" {
		t.Fatalf("expected timeout detail")
	}
}
