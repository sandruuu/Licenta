package devices

import (
	"testing"
	"time"

	"pdp/internal/testdb"
	"pdp/models"
	"pdp/pa/events"
)

func TestAcceptDeviceDataPublishesHealthChangedOnlyForStatusChanges(t *testing.T) {
	dataStore := testdb.NewStore(t)
	publisher := &recordingPublisher{}
	service := NewService(dataStore, nil)
	service.SetEventPublisher(publisher)

	now := time.Unix(1000, 0).UTC()
	first := models.DeviceDataReport{
		DeviceID:    "device-1",
		Hostname:    "host-1",
		OS:          "Windows",
		CollectedAt: now,
		Checks: []models.HealthCheck{{
			Name:        "Firewall",
			Status:      "good",
			Description: "Firewall is enabled",
			Details:     map[string]string{"LastChecked": now.Format(time.RFC3339)},
		}},
	}
	if _, err := service.AcceptDeviceDataReport("device-1", first); err != nil {
		t.Fatalf("AcceptDeviceDataReport first = %v", err)
	}
	if publisher.count(events.TopicHealthChanged) != 1 {
		t.Fatalf("health_changed events after first report = %d, want 1", publisher.count(events.TopicHealthChanged))
	}

	second := first
	second.CollectedAt = now.Add(time.Second)
	second.Checks = []models.HealthCheck{{
		Name:        "Firewall",
		Status:      "good",
		Description: "Firewall was checked again",
		Details:     map[string]string{"LastChecked": now.Add(time.Second).Format(time.RFC3339)},
	}}
	if _, err := service.AcceptDeviceDataReport("device-1", second); err != nil {
		t.Fatalf("AcceptDeviceDataReport second = %v", err)
	}
	if publisher.count(events.TopicHealthChanged) != 1 {
		t.Fatalf("health_changed events after details-only change = %d, want 1", publisher.count(events.TopicHealthChanged))
	}

	third := second
	third.CollectedAt = now.Add(2 * time.Second)
	third.Checks = []models.HealthCheck{{
		Name:        "Firewall",
		Status:      "warning",
		Description: "Firewall state changed",
	}}
	if _, err := service.AcceptDeviceDataReport("device-1", third); err != nil {
		t.Fatalf("AcceptDeviceDataReport third = %v", err)
	}
	if publisher.count(events.TopicHealthChanged) != 2 {
		t.Fatalf("health_changed events after status change = %d, want 2", publisher.count(events.TopicHealthChanged))
	}
}

type recordingPublisher struct {
	events []string
}

func (publisher *recordingPublisher) PublishCAEPEvent(eventType string, _ map[string]string) {
	publisher.events = append(publisher.events, eventType)
}

func (publisher *recordingPublisher) count(eventType string) int {
	count := 0
	for _, observed := range publisher.events {
		if observed == eventType {
			count++
		}
	}
	return count
}
