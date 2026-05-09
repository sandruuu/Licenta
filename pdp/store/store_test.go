package store

import (
	"testing"
	"time"
)

func TestConsumeTokenOnceIsAtomicReplayGuard(t *testing.T) {
	s := New(t.TempDir())
	if err := s.InitDB(); err != nil {
		t.Fatalf("InitDB returned error: %v", err)
	}
	defer s.Close()

	expiresAt := time.Now().Add(5 * time.Minute)
	if !s.ConsumeTokenOnce("jti-1", expiresAt) {
		t.Fatalf("first ConsumeTokenOnce returned false")
	}
	if s.ConsumeTokenOnce("jti-1", expiresAt) {
		t.Fatalf("second ConsumeTokenOnce returned true")
	}
	if !s.IsTokenRevoked("jti-1") {
		t.Fatalf("consumed token was not recorded")
	}
}
