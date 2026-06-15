package agentevents

import (
	"context"
	"strings"
)

const (
	TypeAccessRevoked      = "access.revoked"
	TypeCatalogInvalidated = "catalog.invalidated"
)

type WatchRequest struct {
	AgentSessionToken string
	SessionID         string
}

type Event struct {
	Type           string
	Message        string
	Reason         string
	SessionID      string
	DeviceID       string
	UserID         string
	OrganizationID string
	ResourceID     string
	GatewayID      string
	PolicyID       string
	Action         string
}

func (event Event) NormalizedType() string {
	return strings.ToLower(strings.TrimSpace(event.Type))
}

type Handler func(context.Context, Event) bool

type Client interface {
	Watch(context.Context, WatchRequest, Handler) error
	Close() error
}
