package dataplane

import (
	"context"
	"log"
	"strings"
	"time"

	"gateway/internal/controlplane"
)

func (gateway *Gateway) syncRevokedSerials() {
	if gateway.controlPlane == nil {
		return
	}
	serials, err := gateway.controlPlane.GetRevokedSerials()
	if err != nil {
		log.Printf("[GATEWAY] revocation sync failed: %v", err)
		return
	}
	if len(serials) == 0 {
		return
	}
	gateway.revokedSerials.Range(func(key, _ any) bool {
		gateway.revokedSerials.Delete(key)
		return true
	})
	for _, serial := range serials {
		for _, key := range normalizedSerialKeys(serial) {
			gateway.revokedSerials.Store(key, true)
		}
	}
	log.Printf("[GATEWAY] synced %d revoked certificate serial(s) from PA", len(serials))
}

func (gateway *Gateway) revocationSyncLoop() {
	ticker := time.NewTicker(revocationSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			gateway.syncRevokedSerials()
		case <-gateway.ctx.Done():
			return
		}
	}
}

func (gateway *Gateway) sessionRevalidationLoop() {
	interval := 30 * time.Second
	if gateway != nil && gateway.cfg != nil && gateway.cfg.SessionRevalidationInterval > 0 {
		interval = gateway.cfg.SessionRevalidationInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			gateway.revalidateProvisionedSessions()
		case <-gateway.ctx.Done():
			return
		}
	}
}

func (gateway *Gateway) provisionedSessionCleanupLoop() {
	ticker := time.NewTicker(sessionCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			gateway.cleanupExpiredProvisionedSessions()
		case <-gateway.ctx.Done():
			return
		}
	}
}

func (gateway *Gateway) cleanupExpiredProvisionedSessions() {
	if gateway == nil || gateway.provisioned == nil {
		return
	}
	expired := gateway.provisioned.PurgeExpired()
	if len(expired) == 0 {
		return
	}
	expiredIDs := make(map[string]struct{}, len(expired))
	for _, session := range expired {
		if strings.TrimSpace(session.ID) != "" {
			expiredIDs[session.ID] = struct{}{}
		}
	}
	gateway.terminateRelays(func(relay *activeRelay) bool {
		_, ok := expiredIDs[relay.sessionID]
		return ok
	}, "session.expired")
	log.Printf("[GATEWAY] purged %d expired provisioned session(s)", len(expired))
}

func (gateway *Gateway) revalidateProvisionedSessions() {
	if gateway == nil || gateway.controlPlane == nil || gateway.provisioned == nil {
		return
	}
	sessions := gateway.provisioned.ListSessions()
	if len(sessions) == 0 {
		return
	}
	reported := make([]controlplane.RevalidationSession, 0, len(sessions))
	for _, session := range sessions {
		reported = append(reported, controlplane.RevalidationSession{
			SessionID:  session.ID,
			DeviceID:   session.DeviceID,
			ResourceID: session.ResourceID,
			Protocol:   session.Protocol,
			ExpiresAt:  session.ExpiresAt.UTC().Format(time.RFC3339Nano),
		})
	}
	ctx, cancel := context.WithTimeout(gateway.ctx, sessionRevalidationTimeout)
	defer cancel()
	invalid, err := gateway.controlPlane.RevalidateSessions(ctx, reported)
	if err != nil {
		log.Printf("[GATEWAY] session revalidation failed: %v", err)
		return
	}
	for _, result := range invalid {
		reason := firstNonEmptyString(result.Reason, result.Status, "pa_revalidation_failed")
		gateway.RevokeProvisionedSession(result.SessionID, reason)
	}
	if len(invalid) > 0 {
		log.Printf("[GATEWAY] revalidation revoked %d stale provisioned session(s)", len(invalid))
	}
}
