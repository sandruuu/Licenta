package pa

import (
	"strings"
	"testing"
	"time"

	"pdp/models"
)

func TestStepUpManagerRejectsExpiredCompletion(t *testing.T) {
	manager := NewStepUpManager()
	challenge := newStepUpManagerTestChallenge(t, manager)
	expireStepUpChallengeForTest(t, manager, challenge.ID)

	completed, err := manager.Complete(challenge.ID, "totp", time.Now().UTC())
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("Complete err = %v, want expired", err)
	}
	if completed != nil {
		t.Fatalf("Complete returned challenge after expiry: %+v", completed)
	}
	manager.mu.Lock()
	status := manager.challenges[challenge.ID].Status
	manager.mu.Unlock()
	if status != StepUpStatusExpired {
		t.Fatalf("challenge status = %q, want expired", status)
	}
}

func TestStepUpManagerRejectsExpiredPendingTOTPAndFailedAttempt(t *testing.T) {
	manager := NewStepUpManager()
	challenge := newStepUpManagerTestChallenge(t, manager)
	manager.mu.Lock()
	stored := manager.challenges[challenge.ID]
	stored.Status = StepUpStatusAwaiting
	stored.PendingTOTPSecret = "secret"
	stored.ExpiresAt = time.Now().UTC().Add(-time.Second)
	manager.mu.Unlock()

	if secret, ok := manager.PendingTOTPSecret(challenge.ID); ok || secret != "" {
		t.Fatalf("PendingTOTPSecret = %q ok=%v, want none after expiry", secret, ok)
	}
	updated, retryAllowed := manager.RecordFailedAttempt(challenge.ID, "late attempt")
	if retryAllowed {
		t.Fatal("RecordFailedAttempt allowed retry after expiry")
	}
	if updated == nil || updated.Status != StepUpStatusExpired || strings.TrimSpace(updated.PendingTOTPSecret) != "" {
		t.Fatalf("updated challenge = %+v, want expired with no pending secret", updated)
	}
}

func newStepUpManagerTestChallenge(t *testing.T, manager *StepUpManager) *StepUpChallenge {
	t.Helper()
	challenge, err := manager.CreateChallenge(StepUpChallengeRequest{
		AgentSessionID: "agent-session-1",
		UserID:         "user-1",
		Username:       "alice@example.test",
		TenantID:       "tenant-1",
		DeviceID:       "device-1",
		ResourceID:     "resource-1",
		PublicOrigin:   "https://pdp.example.test",
		Requirement: &models.StepUpRequirement{
			Methods: []string{"totp"},
		},
	})
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	return challenge
}

func expireStepUpChallengeForTest(t *testing.T, manager *StepUpManager, challengeID string) {
	t.Helper()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	challenge := manager.challenges[challengeID]
	if challenge == nil {
		t.Fatalf("challenge %q not found", challengeID)
	}
	challenge.ExpiresAt = time.Now().UTC().Add(-time.Second)
}
