package pa

import (
	"strings"
	"testing"
	"time"

	"pdp/internal/testredis"
	"pdp/models"
)

func TestStepUpManagerRejectsExpiredCompletion(t *testing.T) {
	manager := NewStepUpManager(testredis.NewClient(t))
	challenge := newStepUpManagerTestChallenge(t, manager)
	expireStepUpChallengeForTest(t, manager, challenge.ID)

	completed, err := manager.Complete(challenge.ID, "totp", time.Now().UTC())
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("Complete err = %v, want expired", err)
	}
	if completed != nil {
		t.Fatalf("Complete returned challenge after expiry: %+v", completed)
	}
	stored, ok := manager.Get(challenge.ID)
	if !ok {
		t.Fatalf("challenge %q not found", challenge.ID)
	}
	status := stored.Status
	if status != StepUpStatusExpired {
		t.Fatalf("challenge status = %q, want expired", status)
	}
}

func TestStepUpManagerRejectsExpiredPendingTOTPAndFailedAttempt(t *testing.T) {
	manager := NewStepUpManager(testredis.NewClient(t))
	challenge := newStepUpManagerTestChallenge(t, manager)
	stored, ok := manager.load(challenge.ID)
	if !ok {
		t.Fatalf("challenge %q not found", challenge.ID)
	}
	stored.Status = StepUpStatusAwaiting
	stored.PendingTOTPSecret = "secret"
	stored.ExpiresAt = time.Now().UTC().Add(-time.Second)
	if err := manager.save(stored); err != nil {
		t.Fatalf("save challenge: %v", err)
	}

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

func TestStepUpManagerInvalidatesCompletedAuthContext(t *testing.T) {
	manager := NewStepUpManager(testredis.NewClient(t))
	challenge := newStepUpManagerTestChallenge(t, manager)
	completedAt := time.Now().UTC()
	if _, err := manager.Complete(challenge.ID, "totp", completedAt); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	authContext := manager.AuthContext("agent-session-1", "user-1", "device-1", "resource-1", completedAt.Add(time.Second))
	if authContext.ACR == "" {
		t.Fatal("AuthContext returned no ACR before invalidation")
	}

	if got := manager.InvalidateCompletedAuthContext("user-1", "device-1", "resource-1", "organization-1"); got != 1 {
		t.Fatalf("InvalidateCompletedAuthContext = %d, want 1", got)
	}
	authContext = manager.AuthContext("agent-session-1", "user-1", "device-1", "resource-1", completedAt.Add(2*time.Second))
	if authContext.ACR != "" {
		t.Fatalf("AuthContext ACR after invalidation = %q, want empty", authContext.ACR)
	}
}

func newStepUpManagerTestChallenge(t *testing.T, manager *StepUpManager) *StepUpChallenge {
	t.Helper()
	challenge, err := manager.CreateChallenge(StepUpChallengeRequest{
		AgentSessionID: "agent-session-1",
		UserID:         "user-1",
		Username:       "alice@example.test",
		OrganizationID: "organization-1",
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
	challenge, ok := manager.load(challengeID)
	if !ok || challenge == nil {
		t.Fatalf("challenge %q not found", challengeID)
	}
	challenge.ExpiresAt = time.Now().UTC().Add(-time.Second)
	if err := manager.save(challenge); err != nil {
		t.Fatalf("save challenge: %v", err)
	}
}
