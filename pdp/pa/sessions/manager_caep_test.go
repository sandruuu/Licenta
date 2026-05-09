package sessions

import (
	"testing"
	"time"

	"pdp/models"
	"pdp/store"
)

func newSessionTestStore(t *testing.T) *store.Store {
	t.Helper()
	s := store.New(t.TempDir())
	if err := s.InitDB(); err != nil {
		t.Fatalf("InitDB() error = %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSessionManagerPublishesDeleteEventOnExplicitRevoke(t *testing.T) {
	s := newSessionTestStore(t)
	session := &models.Session{
		ID:        "sess-1",
		UserID:    "user-1",
		Username:  "laura",
		DeviceID:  "device-1",
		Resource:  "10.0.0.5",
		Protocol:  "rdp",
		CreatedAt: time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	s.SaveSession(session)

	sm := NewSessionManager(s, time.Hour, 5)
	var gotSession *models.Session
	var gotReason string
	sm.SetDeleteEventSink(func(session *models.Session, reason string) {
		gotSession = session
		gotReason = reason
	})

	if err := sm.RevokeSession(session.ID); err != nil {
		t.Fatalf("RevokeSession() error = %v", err)
	}
	if gotSession == nil || gotSession.ID != session.ID {
		t.Fatalf("delete event session = %#v, want %s", gotSession, session.ID)
	}
	if gotReason != "admin_revoked" {
		t.Fatalf("delete event reason = %q, want admin_revoked", gotReason)
	}
}

func TestSessionManagerPublishesDeleteEventOnMaxSessionEviction(t *testing.T) {
	s := newSessionTestStore(t)
	old := &models.Session{
		ID:        "sess-old",
		UserID:    "user-1",
		Username:  "laura",
		DeviceID:  "device-old",
		Resource:  "10.0.0.5",
		Protocol:  "rdp",
		CreatedAt: time.Now().Add(-time.Hour),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	s.SaveSession(old)

	sm := NewSessionManager(s, time.Hour, 1)
	var gotSession *models.Session
	var gotReason string
	sm.SetDeleteEventSink(func(session *models.Session, reason string) {
		gotSession = session
		gotReason = reason
	})

	_, err := sm.CreateSession(&models.AccessDecision{RiskScore: 10}, models.AccessRequest{
		UserID:   "user-1",
		Username: "laura",
		DeviceID: "device-new",
		Resource: "10.0.0.6",
		Protocol: "ssh",
	})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	if gotSession == nil || gotSession.ID != old.ID {
		t.Fatalf("eviction event session = %#v, want %s", gotSession, old.ID)
	}
	if gotReason != "max_sessions_exceeded" {
		t.Fatalf("eviction reason = %q, want max_sessions_exceeded", gotReason)
	}
}

func TestSessionManagerPublishesDeleteEventOnExpiredCleanup(t *testing.T) {
	s := newSessionTestStore(t)
	session := &models.Session{
		ID:        "sess-expired",
		UserID:    "user-1",
		Username:  "laura",
		DeviceID:  "device-1",
		Resource:  "res-ssh",
		Protocol:  "ssh",
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	s.SaveSession(session)

	sm := NewSessionManager(s, time.Hour, 5)
	var gotSession *models.Session
	var gotReason string
	sm.SetDeleteEventSink(func(session *models.Session, reason string) {
		gotSession = session
		gotReason = reason
	})

	if count := sm.CleanupExpired(); count != 1 {
		t.Fatalf("CleanupExpired() = %d, want 1", count)
	}
	if gotSession == nil || gotSession.ID != session.ID {
		t.Fatalf("expired event session = %#v, want %s", gotSession, session.ID)
	}
	if gotReason != "expired" {
		t.Fatalf("expired reason = %q, want expired", gotReason)
	}
	if _, ok := s.GetSession(session.ID); ok {
		t.Fatalf("expired session %s still exists", session.ID)
	}
}
