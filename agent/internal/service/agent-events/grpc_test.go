package agentevents

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
)

func TestEventFromStructParsesEventTime(t *testing.T) {
	message, err := structpb.NewStruct(map[string]any{
		"type":       TypeStepUpCompleted,
		"event_time": "2026-06-29T13:22:26.865538204Z",
		"message":    "Security verification completed.",
	})
	if err != nil {
		t.Fatalf("NewStruct returned error: %v", err)
	}

	event := eventFromStruct(message)
	want := time.Date(2026, 6, 29, 13, 22, 26, 865538204, time.UTC)
	if !event.Time.Equal(want) {
		t.Fatalf("event time = %s, want %s", event.Time.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}
}
