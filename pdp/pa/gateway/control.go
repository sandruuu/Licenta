package gateway

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"pdp/models"
	"pdp/util"

	"google.golang.org/protobuf/types/known/structpb"
)

const (
	CommandProvisionSession = "provision_session"
	CommandRevokeSession    = "revoke_session"
	CommandHeartbeat        = "heartbeat"
)

var (
	ErrControlNotConnected   = errors.New("gateway control stream is not connected")
	ErrControlStreamReplaced = errors.New("gateway control stream was replaced")
)

type ProvisionedSession struct {
	ID               string
	SessionToken     string
	DeviceID         string
	UserID           string
	Username         string
	ResourceID       string
	ResourceName     string
	InternalHost     string
	InternalPort     int
	Protocol         string
	ExpiresAt        time.Time
	Constraints      []string
	PolicyVersion    string
	MaxBandwidthMbps int
}

type ControlRegistry struct {
	mu          sync.RWMutex
	connections map[string]*ControlConnection
	now         func() time.Time
}

type ControlConnection struct {
	gatewayID   string
	fqdn        string
	endpoint    string
	connectedAt time.Time
	commands    chan controlEnvelope
	done        chan struct{}
	closeOnce   sync.Once
}

type controlEnvelope struct {
	command *structpb.Struct
	result  chan error
}

func NewControlRegistry() *ControlRegistry {
	return &ControlRegistry{
		connections: make(map[string]*ControlConnection),
		now:         time.Now,
	}
}

func (registry *ControlRegistry) ConnectedGatewayIDs() []string {
	if registry == nil {
		return nil
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	ids := make([]string, 0, len(registry.connections))
	for gatewayID := range registry.connections {
		ids = append(ids, gatewayID)
	}
	sort.Strings(ids)
	return ids
}

func (registry *ControlRegistry) ProvisionSession(ctx context.Context, gatewayID string, session ProvisionedSession) error {
	if err := validateProvisionedSession(session); err != nil {
		return err
	}
	sessionMap := map[string]interface{}{
		"session_id":         strings.TrimSpace(session.ID),
		"session_token":      strings.TrimSpace(session.SessionToken),
		"device_id":          strings.TrimSpace(session.DeviceID),
		"user_id":            strings.TrimSpace(session.UserID),
		"username":           strings.TrimSpace(session.Username),
		"resource_id":        strings.TrimSpace(session.ResourceID),
		"resource_name":      strings.TrimSpace(session.ResourceName),
		"internal_host":      strings.TrimSpace(session.InternalHost),
		"internal_port":      float64(session.InternalPort),
		"protocol":           strings.TrimSpace(session.Protocol),
		"expires_at":         session.ExpiresAt.UTC().Format(time.RFC3339Nano),
		"constraints":        stringSliceValues(session.Constraints),
		"policy_version":     strings.TrimSpace(session.PolicyVersion),
		"max_bandwidth_mbps": float64(session.MaxBandwidthMbps),
	}
	command, err := controlCommand(CommandProvisionSession, map[string]interface{}{"session": sessionMap})
	if err != nil {
		return err
	}
	return registry.send(ctx, gatewayID, command)
}

func (registry *ControlRegistry) RevokeSession(ctx context.Context, gatewayID, sessionID, reason string) error {
	if strings.TrimSpace(sessionID) == "" {
		return errors.New("session_id is required")
	}
	command, err := controlCommand(CommandRevokeSession, map[string]interface{}{
		"session_id": strings.TrimSpace(sessionID),
		"reason":     strings.TrimSpace(reason),
	})
	if err != nil {
		return err
	}
	return registry.send(ctx, gatewayID, command)
}

func (registry *ControlRegistry) Heartbeat(ctx context.Context, gatewayID string) error {
	command, err := controlCommand(CommandHeartbeat, nil)
	if err != nil {
		return err
	}
	return registry.send(ctx, gatewayID, command)
}

func (registry *ControlRegistry) Register(gateway *models.Gateway, endpoint string) *ControlConnection {
	if registry == nil || gateway == nil {
		return nil
	}
	if registry.now == nil {
		registry.now = time.Now
	}
	connection := &ControlConnection{
		gatewayID:   strings.TrimSpace(gateway.ID),
		fqdn:        strings.TrimSpace(gateway.FQDN),
		endpoint:    strings.TrimSpace(endpoint),
		connectedAt: registry.now().UTC(),
		commands:    make(chan controlEnvelope, 32),
		done:        make(chan struct{}),
	}
	registry.mu.Lock()
	if previous := registry.connections[connection.gatewayID]; previous != nil {
		previous.Close()
	}
	registry.connections[connection.gatewayID] = connection
	registry.mu.Unlock()
	return connection
}

func (registry *ControlRegistry) Unregister(connection *ControlConnection) {
	if registry == nil || connection == nil {
		return
	}
	registry.mu.Lock()
	if registry.connections[connection.gatewayID] == connection {
		delete(registry.connections, connection.gatewayID)
		connection.Close()
	}
	registry.mu.Unlock()
}

func (registry *ControlRegistry) send(ctx context.Context, gatewayID string, command *structpb.Struct) error {
	if registry == nil {
		return ErrControlNotConnected
	}
	gatewayID = strings.TrimSpace(gatewayID)
	if gatewayID == "" {
		return errors.New("gateway_id is required")
	}
	registry.mu.RLock()
	connection := registry.connections[gatewayID]
	registry.mu.RUnlock()
	if connection == nil {
		return fmt.Errorf("%w: %s", ErrControlNotConnected, gatewayID)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	envelope := controlEnvelope{command: command, result: make(chan error, 1)}
	select {
	case connection.commands <- envelope:
	case <-connection.done:
		return fmt.Errorf("%w: %s", ErrControlNotConnected, gatewayID)
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-envelope.result:
		return err
	case <-connection.done:
		return fmt.Errorf("%w: %s", ErrControlNotConnected, gatewayID)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (connection *ControlConnection) Close() {
	if connection == nil {
		return
	}
	connection.closeOnce.Do(func() { close(connection.done) })
}

func (connection *ControlConnection) Serve(ctx context.Context, send func(*structpb.Struct) error) error {
	if connection == nil {
		return ErrControlNotConnected
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if send == nil {
		return errors.New("gateway control sender is required")
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-connection.done:
			return ErrControlStreamReplaced
		case envelope := <-connection.commands:
			envelope.result <- send(envelope.command)
		}
	}
}

func validateProvisionedSession(session ProvisionedSession) error {
	checks := map[string]string{
		"session_id":    session.ID,
		"session_token": session.SessionToken,
		"device_id":     session.DeviceID,
		"resource_id":   session.ResourceID,
		"internal_host": session.InternalHost,
		"protocol":      session.Protocol,
	}
	for name, value := range checks {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if session.InternalPort <= 0 {
		return errors.New("internal_port must be positive")
	}
	if session.ExpiresAt.IsZero() {
		return errors.New("expires_at is required")
	}
	if !session.ExpiresAt.After(time.Now()) {
		return errors.New("expires_at must be in the future")
	}
	if session.MaxBandwidthMbps < 0 {
		return errors.New("max_bandwidth_mbps must be non-negative")
	}
	return nil
}

func controlCommand(commandType string, fields map[string]interface{}) (*structpb.Struct, error) {
	commandID, err := util.GenerateID("gwcmd")
	if err != nil {
		return nil, fmt.Errorf("generate gateway control command ID: %w", err)
	}
	payload := map[string]interface{}{
		"type":       commandType,
		"command_id": commandID,
		"sent_at":    time.Now().UTC().Format(time.RFC3339Nano),
	}
	for key, value := range fields {
		payload[key] = value
	}
	command, err := structpb.NewStruct(payload)
	if err != nil {
		return nil, fmt.Errorf("build gateway control command: %w", err)
	}
	return command, nil
}

func stringSliceValues(values []string) []interface{} {
	items := make([]interface{}, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			items = append(items, trimmed)
		}
	}
	return items
}
