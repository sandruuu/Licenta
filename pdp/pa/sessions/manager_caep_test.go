package sessions

import (
	"testing"
	"time"

	"pdp/internal/testdb"
	"pdp/models"
	"pdp/store"
)

func newSessionTestStore(t *testing.T) *store.Store {
	t.Helper()
	return testdb.NewStore(t)
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

func TestSessionManagerRevokesDeviceUserSessionsOnAgentLogout(t *testing.T) {
	s := newSessionTestStore(t)
	now := time.Now()
	matchingOne := &models.Session{
		ID:             "sess-match-1",
		UserID:         "user-1",
		Username:       "laura",
		DeviceID:       "device-1",
		Resource:       "res-ssh",
		Protocol:       "ssh",
		OrganizationID: "organization-1",
		CreatedAt:      now.Add(-time.Minute),
		ExpiresAt:      now.Add(time.Hour),
	}
	matchingTwo := &models.Session{
		ID:             "sess-match-2",
		UserID:         "user-1",
		Username:       "laura",
		DeviceID:       "device-1",
		Resource:       "res-web",
		Protocol:       "https",
		OrganizationID: "organization-1",
		CreatedAt:      now.Add(-time.Minute),
		ExpiresAt:      now.Add(time.Hour),
	}
	otherDevice := &models.Session{
		ID:             "sess-other-device",
		UserID:         "user-1",
		Username:       "laura",
		DeviceID:       "device-2",
		Resource:       "res-rdp",
		Protocol:       "rdp",
		OrganizationID: "organization-1",
		CreatedAt:      now.Add(-time.Minute),
		ExpiresAt:      now.Add(time.Hour),
	}
	otherOrganization := &models.Session{
		ID:             "sess-other-organization",
		UserID:         "user-1",
		Username:       "laura",
		DeviceID:       "device-1",
		Resource:       "res-db",
		Protocol:       "tcp",
		OrganizationID: "organization-2",
		CreatedAt:      now.Add(-time.Minute),
		ExpiresAt:      now.Add(time.Hour),
	}
	s.SaveSession(matchingOne)
	s.SaveSession(matchingTwo)
	s.SaveSession(otherDevice)
	s.SaveSession(otherOrganization)

	sm := NewSessionManager(s, time.Hour, 10)
	var deleted []string
	var reasons []string
	sm.SetDeleteEventSink(func(session *models.Session, reason string) {
		deleted = append(deleted, session.ID)
		reasons = append(reasons, reason)
	})

	if got := sm.RevokeSessionsForDeviceUser("user-1", "device-1", "organization-1", "agent_logout"); got != 2 {
		t.Fatalf("RevokeSessionsForDeviceUser() = %d, want 2", got)
	}
	for _, id := range []string{matchingOne.ID, matchingTwo.ID} {
		session, ok := s.GetSession(id)
		if !ok || !session.Revoked {
			t.Fatalf("session %s revoked = %v, found=%v", id, ok && session.Revoked, ok)
		}
	}
	for _, id := range []string{otherDevice.ID, otherOrganization.ID} {
		session, ok := s.GetSession(id)
		if !ok || session.Revoked {
			t.Fatalf("session %s should remain active, session=%#v found=%v", id, session, ok)
		}
	}
	if len(deleted) != 2 || len(reasons) != 2 {
		t.Fatalf("delete events = %v reasons=%v, want 2 events", deleted, reasons)
	}
	for _, reason := range reasons {
		if reason != "agent_logout" {
			t.Fatalf("delete reason = %q, want agent_logout", reason)
		}
	}
}

func TestSessionManagerRevokesSessionsByEnterpriseScopes(t *testing.T) {
	s := newSessionTestStore(t)
	now := time.Now()
	sessions := []*models.Session{
		{
			ID:             "sess-device",
			UserID:         "user-1",
			Username:       "laura",
			DeviceID:       "device-1",
			Resource:       "res-ssh",
			GatewayID:      "gw-1",
			Protocol:       "ssh",
			OrganizationID: "organization-1",
			CreatedAt:      now.Add(-time.Minute),
			ExpiresAt:      now.Add(time.Hour),
		},
		{
			ID:             "sess-resource",
			UserID:         "user-2",
			Username:       "alex",
			DeviceID:       "device-2",
			Resource:       "res-web",
			GatewayID:      "gw-1",
			Protocol:       "https",
			OrganizationID: "organization-1",
			CreatedAt:      now.Add(-time.Minute),
			ExpiresAt:      now.Add(time.Hour),
		},
		{
			ID:             "sess-gateway-other-organization",
			UserID:         "user-3",
			Username:       "mara",
			DeviceID:       "device-3",
			Resource:       "res-db",
			GatewayID:      "gw-1",
			Protocol:       "tcp",
			OrganizationID: "organization-2",
			CreatedAt:      now.Add(-time.Minute),
			ExpiresAt:      now.Add(time.Hour),
		},
	}
	for _, session := range sessions {
		s.SaveSession(session)
	}

	sm := NewSessionManager(s, time.Hour, 10)
	var deleted []string
	var reasons []string
	sm.SetDeleteEventSink(func(session *models.Session, reason string) {
		deleted = append(deleted, session.ID)
		reasons = append(reasons, reason)
	})

	if got := sm.RevokeSessionsForDevice("device-1", "organization-1", "device_revoked"); got != 1 {
		t.Fatalf("RevokeSessionsForDevice() = %d, want 1", got)
	}
	if got := sm.RevokeSessionsForResource("res-web", "organization-1", "resource_disabled"); got != 1 {
		t.Fatalf("RevokeSessionsForResource() = %d, want 1", got)
	}
	if got := sm.RevokeSessionsForGateway("gw-1", "organization-2", "gateway_revoked"); got != 1 {
		t.Fatalf("RevokeSessionsForGateway() = %d, want 1", got)
	}

	for _, session := range sessions {
		saved, ok := s.GetSession(session.ID)
		if !ok || !saved.Revoked {
			t.Fatalf("session %s revoked = %v, found=%v", session.ID, ok && saved.Revoked, ok)
		}
	}
	if len(deleted) != 3 || len(reasons) != 3 {
		t.Fatalf("delete events = %v reasons=%v, want 3", deleted, reasons)
	}
	wantReasons := map[string]bool{
		"device_revoked":    true,
		"resource_disabled": true,
		"gateway_revoked":   true,
	}
	for _, reason := range reasons {
		if !wantReasons[reason] {
			t.Fatalf("unexpected revoke reason %q", reason)
		}
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

	_, err := sm.CreateSession(&models.AccessDecision{}, models.AccessRequest{
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

func TestSessionManagerReusesAndRenewsResourceSession(t *testing.T) {
	s := newSessionTestStore(t)
	sm := NewSessionManager(s, 10*time.Minute, 5)
	req := models.AccessRequest{
		UserID:         "user-1",
		Username:       "laura",
		DeviceID:       "device-1",
		Resource:       "res-ssh",
		GatewayID:      "gw-1",
		Protocol:       "ssh",
		OrganizationID: "organization-1",
	}
	first, reused, err := sm.CreateOrRenewSession(&models.AccessDecision{RiskSignals: []string{"new_location"}}, req, time.Minute)
	if err != nil {
		t.Fatalf("CreateOrRenewSession() first error = %v", err)
	}
	if reused {
		t.Fatal("first CreateOrRenewSession() reused an existing session")
	}
	first.ExpiresAt = time.Now().Add(20 * time.Second)
	s.SaveSession(first)

	second, reused, err := sm.CreateOrRenewSession(&models.AccessDecision{RiskSignals: []string{"device_non_compliant"}}, req, time.Minute)
	if err != nil {
		t.Fatalf("CreateOrRenewSession() second error = %v", err)
	}
	if !reused {
		t.Fatal("second CreateOrRenewSession() did not reuse existing session")
	}
	if second.ID != first.ID {
		t.Fatalf("session id = %s, want reused %s", second.ID, first.ID)
	}
	if time.Until(second.ExpiresAt) < 9*time.Minute {
		t.Fatalf("session was not renewed far enough: expires=%s", second.ExpiresAt)
	}
	if len(second.RiskSignals) != 1 || second.RiskSignals[0] != "device_non_compliant" {
		t.Fatalf("risk signals = %v, want renewed decision signals", second.RiskSignals)
	}
}

func TestSessionManagerDoesNotReuseResourceSessionWhenSourceIPChanges(t *testing.T) {
	s := newSessionTestStore(t)
	sm := NewSessionManager(s, 10*time.Minute, 5)
	req := models.AccessRequest{
		UserID:         "user-1",
		Username:       "laura",
		DeviceID:       "device-1",
		SourceIP:       "5.14.130.142",
		Resource:       "res-rdp",
		GatewayID:      "gw-1",
		Protocol:       "rdp",
		OrganizationID: "organization-1",
	}

	first, reused, err := sm.CreateOrRenewSession(&models.AccessDecision{}, req, time.Minute)
	if err != nil {
		t.Fatalf("CreateOrRenewSession() first error = %v", err)
	}
	if reused {
		t.Fatal("first CreateOrRenewSession() reused an existing session")
	}

	req.SourceIP = "185.238.28.51"
	second, reused, err := sm.CreateOrRenewSession(&models.AccessDecision{}, req, time.Minute)
	if err != nil {
		t.Fatalf("CreateOrRenewSession() second error = %v", err)
	}
	if reused {
		t.Fatal("second CreateOrRenewSession() reused a session from a different source IP")
	}
	if second.ID == first.ID {
		t.Fatalf("session id = %s, want a new session after source IP change", second.ID)
	}
}

func TestSessionManagerRevokesResourceSessionWhenSourceIPChanges(t *testing.T) {
	s := newSessionTestStore(t)
	now := time.Now()
	matching := &models.Session{
		ID:             "sess-old-ip",
		UserID:         "user-1",
		Username:       "laura",
		DeviceID:       "device-1",
		SourceIP:       "5.14.130.142",
		Resource:       "res-rdp",
		GatewayID:      "gw-1",
		Protocol:       "rdp",
		OrganizationID: "organization-1",
		CreatedAt:      now.Add(-time.Minute),
		ExpiresAt:      now.Add(time.Hour),
	}
	otherResource := &models.Session{
		ID:             "sess-other-resource",
		UserID:         "user-1",
		Username:       "laura",
		DeviceID:       "device-1",
		SourceIP:       "5.14.130.142",
		Resource:       "res-web",
		GatewayID:      "gw-1",
		Protocol:       "https",
		OrganizationID: "organization-1",
		CreatedAt:      now.Add(-time.Minute),
		ExpiresAt:      now.Add(time.Hour),
	}
	otherUser := &models.Session{
		ID:             "sess-other-user",
		UserID:         "user-2",
		Username:       "alex",
		DeviceID:       "device-1",
		SourceIP:       "5.14.130.142",
		Resource:       "res-rdp",
		GatewayID:      "gw-1",
		Protocol:       "rdp",
		OrganizationID: "organization-1",
		CreatedAt:      now.Add(-time.Minute),
		ExpiresAt:      now.Add(time.Hour),
	}
	s.SaveSession(matching)
	s.SaveSession(otherResource)
	s.SaveSession(otherUser)

	sm := NewSessionManager(s, 10*time.Minute, 5)
	var gotSession *models.Session
	var gotReason string
	sm.SetDeleteEventSink(func(session *models.Session, reason string) {
		gotSession = session
		gotReason = reason
	})
	revoked := sm.RevokeSessionsForChangedSourceIP(models.AccessRequest{
		UserID:         "user-1",
		Username:       "laura",
		DeviceID:       "device-1",
		SourceIP:       "185.238.28.51",
		Resource:       "res-rdp",
		GatewayID:      "gw-1",
		Protocol:       "rdp",
		OrganizationID: "organization-1",
	})
	if revoked != 1 {
		t.Fatalf("RevokeSessionsForChangedSourceIP() = %d, want 1", revoked)
	}
	if gotSession == nil || gotSession.ID != matching.ID || gotReason != "source_ip_changed" {
		t.Fatalf("delete event session=%#v reason=%q, want %s/source_ip_changed", gotSession, gotReason, matching.ID)
	}
	saved, ok := s.GetSession(matching.ID)
	if !ok || !saved.Revoked {
		t.Fatalf("matching session revoked = %v, found=%v", ok && saved.Revoked, ok)
	}
	for _, id := range []string{otherResource.ID, otherUser.ID} {
		session, ok := s.GetSession(id)
		if !ok || session.Revoked {
			t.Fatalf("session %s should remain active, session=%#v found=%v", id, session, ok)
		}
	}
}

func TestSessionManagerAppliesPolicySessionControls(t *testing.T) {
	s := newSessionTestStore(t)
	sm := NewSessionManager(s, time.Hour, 5)
	req := models.AccessRequest{
		UserID:         "user-1",
		Username:       "laura",
		DeviceID:       "device-1",
		Resource:       "res-admin",
		GatewayID:      "gw-1",
		Protocol:       "https",
		OrganizationID: "organization-1",
	}
	start := time.Now()
	session, reused, err := sm.CreateOrRenewSession(&models.AccessDecision{
		RiskSignals: []string{"device_non_compliant"},
		MatchedRule: "policy-session-controls",
		SessionControls: models.SessionPolicyControls{
			MaxAgeSeconds:          600,
			RevalidateEverySeconds: 60,
			RevokeOnPostureChange:  true,
		},
	}, req, time.Minute)
	if err != nil {
		t.Fatalf("CreateOrRenewSession() error = %v", err)
	}
	if reused {
		t.Fatal("first CreateOrRenewSession() reused an existing session")
	}
	if session.PolicyID != "policy-session-controls" {
		t.Fatalf("PolicyID = %q, want policy-session-controls", session.PolicyID)
	}
	if session.SessionMaxAgeSeconds != 600 || session.RevalidateEverySeconds != 60 {
		t.Fatalf("session controls not persisted: %+v", session)
	}
	if !session.RevokeOnPostureChange {
		t.Fatalf("posture revocation control not persisted: %+v", session)
	}
	if len(session.RiskSignals) != 1 || session.RiskSignals[0] != "device_non_compliant" {
		t.Fatalf("risk signals not persisted on session: %+v", session)
	}
	if session.ExpiresAt.Before(start.Add(55*time.Second)) || session.ExpiresAt.After(start.Add(65*time.Second)) {
		t.Fatalf("ExpiresAt = %s, want about 60s from start %s", session.ExpiresAt, start)
	}
	if session.RevalidateAfter.Before(start.Add(55*time.Second)) || session.RevalidateAfter.After(start.Add(65*time.Second)) {
		t.Fatalf("RevalidateAfter = %s, want about 60s from start %s", session.RevalidateAfter, start)
	}

	saved, ok := s.GetSession(session.ID)
	if !ok {
		t.Fatalf("saved session %s not found", session.ID)
	}
	if saved.PolicyID != session.PolicyID || saved.RevalidateEverySeconds != 60 {
		t.Fatalf("saved session controls = %+v, want persisted controls", saved)
	}
}

func TestSessionManagerCapsRenewalAtPolicyMaxAge(t *testing.T) {
	s := newSessionTestStore(t)
	sm := NewSessionManager(s, time.Hour, 5)
	now := time.Now()
	req := models.AccessRequest{
		UserID:         "user-1",
		Username:       "laura",
		DeviceID:       "device-1",
		Resource:       "res-admin",
		GatewayID:      "gw-1",
		Protocol:       "https",
		OrganizationID: "organization-1",
	}
	existing := &models.Session{
		ID:                   "sess-policy-max-age",
		UserID:               req.UserID,
		Username:             req.Username,
		DeviceID:             req.DeviceID,
		Resource:             req.Resource,
		GatewayID:            req.GatewayID,
		Protocol:             req.Protocol,
		OrganizationID:       req.OrganizationID,
		CreatedAt:            now.Add(-115 * time.Second),
		ExpiresAt:            now.Add(20 * time.Second),
		LastActivity:         now.Add(-time.Minute),
		SessionMaxAgeSeconds: 120,
	}
	s.SaveSession(existing)

	renewed, reused, err := sm.CreateOrRenewSession(&models.AccessDecision{
		MatchedRule: "policy-short-session",
		SessionControls: models.SessionPolicyControls{
			MaxAgeSeconds: 120,
		},
	}, req, time.Minute)
	if err != nil {
		t.Fatalf("CreateOrRenewSession() error = %v", err)
	}
	if !reused || renewed.ID != existing.ID {
		t.Fatalf("session reuse = %v id=%s, want reused %s", reused, renewed.ID, existing.ID)
	}
	maxExpiresAt := existing.CreatedAt.Add(120 * time.Second)
	if renewed.ExpiresAt.After(maxExpiresAt.Add(2 * time.Second)) {
		t.Fatalf("ExpiresAt = %s, want capped near %s", renewed.ExpiresAt, maxExpiresAt)
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
