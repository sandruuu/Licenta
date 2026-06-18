package dataplane

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gateway/internal/config"
	"gateway/internal/controlplane"
	"gateway/internal/provisioning"
)

type Gateway struct {
	cfg          *config.Config
	controlPlane *controlplane.Client
	relay        *Relay

	provisioned *provisioning.Store

	ctx    context.Context
	cancel context.CancelFunc

	activeConns atomic.Int64
	perIPConns  sync.Map

	revokedSerials sync.Map
	activeRelays   sync.Map
}

type connectionState struct {
	remoteAddr   string
	certDeviceID string
}

type activeRelay struct {
	id         string
	sessionID  string
	deviceID   string
	resourceID string
	renew      chan time.Time
	cancel     func(reason string)
}

func New(cfg *config.Config, controlPlaneClient *controlplane.Client, relayManager *Relay) *Gateway {
	if relayManager == nil {
		relayManager = NewRelay(relayDialTimeout)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Gateway{
		cfg:          cfg,
		controlPlane: controlPlaneClient,
		relay:        relayManager,
		provisioned:  provisioning.NewStore(),
		ctx:          ctx,
		cancel:       cancel,
	}
}

func (gateway *Gateway) ProvisionSession(session provisioning.Session, sessionToken string) error {
	if gateway.provisioned == nil {
		gateway.provisioned = provisioning.NewStore()
	}
	if err := gateway.provisioned.Provision(session, sessionToken); err != nil {
		return err
	}
	gateway.renewActiveRelays(session.ID, session.ExpiresAt)
	log.Printf("[GATEWAY] PA provisioned session %s for device=%s resource=%s target=%s:%d expires=%s",
		session.ID, session.DeviceID, session.ResourceID, session.InternalHost, session.InternalPort, session.ExpiresAt.Format(time.RFC3339))
	return nil
}

func (gateway *Gateway) RevokeProvisionedSession(sessionID, reason string) bool {
	if gateway.provisioned == nil {
		return false
	}
	session, ok := gateway.provisioned.Revoke(sessionID, reason)
	if !ok {
		return false
	}
	gateway.terminateRelays(func(relay *activeRelay) bool {
		return relay.sessionID == session.ID
	}, "session.revoked")
	log.Printf("[GATEWAY] PA revoked session %s reason=%s", sessionID, strings.TrimSpace(reason))
	return true
}

func (gateway *Gateway) ProvisionedSessionCount() int {
	if gateway == nil || gateway.provisioned == nil {
		return 0
	}
	return gateway.provisioned.Count()
}

func (gateway *Gateway) ListenAndServe() error {
	if gateway.cfg == nil {
		return fmt.Errorf("gateway config is required")
	}
	listener, err := gateway.listen()
	if err != nil {
		return err
	}
	defer listener.Close()

	go func() {
		<-gateway.ctx.Done()
		_ = listener.Close()
	}()

	gateway.syncRevokedSerials()
	gateway.cleanupExpiredProvisionedSessions()
	go gateway.revocationSyncLoop()
	go gateway.provisionedSessionCleanupLoop()
	go gateway.sessionRevalidationLoop()
	go gateway.certExpiryLoop()

	log.Printf("[GATEWAY] strict PEP listening on %s", agentListenAddr)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if gateway.ctx.Err() != nil {
				return nil
			}
			log.Printf("[GATEWAY] accept failed: %v", err)
			continue
		}
		go gateway.handleConnection(conn)
	}
}

func (gateway *Gateway) Shutdown() {
	if gateway.cancel != nil {
		gateway.cancel()
	}
	gateway.terminateRelays(func(*activeRelay) bool { return true }, "gateway.shutdown")
}
