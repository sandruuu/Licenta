package service

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	agentevents "agent/internal/service/agent-events"
	"agent/internal/service/usersession"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const agentEventSyncInterval = 2 * time.Second

type agentEventWatcher struct {
	cancel context.CancelFunc
}

func (service *Service) runAgentEvents(ctx context.Context) {
	if service == nil || service.agentEventsFactory == nil || service.userSessions == nil || service.enrollment == nil {
		return
	}
	watchers := map[string]agentEventWatcher{}
	done := make(chan string, 16)
	ticker := time.NewTicker(agentEventSyncInterval)
	defer ticker.Stop()
	defer func() {
		for _, active := range watchers {
			if active.cancel != nil {
				active.cancel()
			}
		}
	}()

	for {
		service.syncAgentEventWatchers(ctx, watchers, done)
		select {
		case <-ctx.Done():
			return
		case sessionID := <-done:
			if active, ok := watchers[sessionID]; ok {
				if active.cancel != nil {
					active.cancel()
				}
				delete(watchers, sessionID)
			}
		case <-ticker.C:
		}
	}
}

func (service *Service) syncAgentEventWatchers(ctx context.Context, watchers map[string]agentEventWatcher, done chan<- string) {
	activeSessions := service.userSessions.ActiveAuthenticatedSessions()
	activeIDs := map[string]usersession.AuthenticatedSession{}
	for _, session := range activeSessions {
		sessionID := strings.TrimSpace(session.AgentSessionID)
		if sessionID == "" || strings.TrimSpace(session.AgentSessionToken) == "" {
			continue
		}
		activeIDs[sessionID] = session
		if _, exists := watchers[sessionID]; exists {
			continue
		}
		watchCtx, cancel := context.WithCancel(ctx)
		watchers[sessionID] = agentEventWatcher{cancel: cancel}
		go func(session usersession.AuthenticatedSession) {
			defer func() {
				select {
				case done <- session.AgentSessionID:
				default:
				}
			}()
			service.watchAgentSessionEvents(watchCtx, session)
		}(session)
	}
	for sessionID, active := range watchers {
		if _, ok := activeIDs[sessionID]; ok {
			continue
		}
		if active.cancel != nil {
			active.cancel()
		}
		delete(watchers, sessionID)
	}
}

func (service *Service) watchAgentSessionEvents(ctx context.Context, session usersession.AuthenticatedSession) {
	record, err := service.enrollment.Record(ctx)
	if err != nil {
		if ctx.Err() == nil {
			service.logger.Warn("agent event stream cannot load enrollment", "session_id", session.AgentSessionID, "error", err)
		}
		return
	}
	client, err := service.agentEventsFactory(ctx, record)
	if err != nil {
		if ctx.Err() == nil {
			service.logger.Warn("agent event stream cannot connect", "session_id", session.AgentSessionID, "error", err)
		}
		return
	}
	defer func() {
		if err := client.Close(); err != nil {
			service.logger.Debug("agent event client close failed", "error", err)
		}
	}()

	err = client.Watch(ctx, agentevents.WatchRequest{
		AgentSessionToken: session.AgentSessionToken,
		SessionID:         session.AgentSessionID,
	}, func(eventCtx context.Context, event agentevents.Event) bool {
		return service.handleAgentEvent(eventCtx, session, event)
	})
	if err == nil || errors.Is(err, context.Canceled) || ctx.Err() != nil {
		return
	}
	if code := status.Code(err); code == codes.Unauthenticated || code == codes.PermissionDenied {
		service.userSessions.RevokeRemote(context.Background(), session.AgentSessionID, "Your session is no longer valid. Sign in again to access protected resources.")
		return
	}
	service.logger.Warn("agent event stream stopped", slog.String("session_id", session.AgentSessionID), slog.Any("error", err))
}

func (service *Service) handleAgentEvent(ctx context.Context, session usersession.AuthenticatedSession, event agentevents.Event) bool {
	switch event.NormalizedType() {
	case agentevents.TypeAccessRevoked:
		message := firstNonEmptyServiceString(event.Message, "Protected resource access was revoked. Sign in again to continue.")
		eventSessionID := strings.TrimSpace(event.SessionID)
		if eventSessionID == "" || eventSessionID == session.AgentSessionID {
			if service.userSessions.RevokeRemote(ctx, firstNonEmptyServiceString(eventSessionID, session.AgentSessionID), message) {
				return false
			}
		}
		service.userSessions.SetAuthenticatedMessage(message)
		if strings.EqualFold(strings.TrimSpace(event.Reason), "device_posture_changed") {
			service.pauseProtectedResourcesFromRemoteEvent(ctx, message)
		}
		return true
	case agentevents.TypeCatalogInvalidated:
		if err := service.userSessions.RefreshCatalog(ctx, firstNonEmptyServiceString(event.SessionID, session.AgentSessionID)); err != nil {
			if code := status.Code(err); code == codes.Unauthenticated || code == codes.PermissionDenied {
				service.userSessions.RevokeRemote(context.Background(), session.AgentSessionID, "Your session is no longer valid. Sign in again to access protected resources.")
				return false
			}
			service.logger.Warn("failed to refresh protected resource catalog after PDP event", "session_id", session.AgentSessionID, "reason", event.Reason, "error", err)
		}
		return true
	case agentevents.TypeStepUpCompleted:
		service.userSessions.MarkAuthenticatedStepUpCompleted(
			firstNonEmptyServiceString(event.SessionID, session.AgentSessionID),
			event.ResourceID,
			"",
		)
		return true
	default:
		return true
	}
}

func firstNonEmptyServiceString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
