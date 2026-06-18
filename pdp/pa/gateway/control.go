package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"pdp/models"
	"pdp/runtime/redisstate"
	"pdp/util"

	"google.golang.org/protobuf/types/known/structpb"
)

const (
	CommandProvisionSession = "provision_session"
	CommandRevokeSession    = "revoke_session"
	CommandHeartbeat        = "heartbeat"

	gatewayControlPresenceTTL = 5 * time.Second
	gatewayControlResultTTL   = time.Minute
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
	ExternalPort     int
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
	runtime     *redisstate.Client
	instanceID  string
}

type ControlConnection struct {
	registry    *ControlRegistry
	gatewayID   string
	fqdn        string
	endpoint    string
	ownerID     string
	connectedAt time.Time
	done        chan struct{}
	closeOnce   sync.Once
}

func NewControlRegistry(runtimeState *redisstate.Client) *ControlRegistry {
	instanceID := ""
	if runtimeState != nil {
		instanceID = runtimeState.InstanceID()
	}
	if instanceID == "" {
		instanceID, _ = util.GenerateID("pdp")
	}
	return &ControlRegistry{
		connections: make(map[string]*ControlConnection),
		now:         time.Now,
		runtime:     runtimeState,
		instanceID:  instanceID,
	}
}

func (registry *ControlRegistry) ConnectedGatewayIDs() []string {
	if registry == nil {
		return nil
	}
	if registry.runtime == nil {
		registry.mu.RLock()
		defer registry.mu.RUnlock()
		ids := make([]string, 0, len(registry.connections))
		for gatewayID := range registry.connections {
			ids = append(ids, gatewayID)
		}
		sort.Strings(ids)
		return ids
	}
	presence, err := registry.runtime.ListGatewayPresence(context.Background())
	if err != nil {
		return nil
	}
	ids := make([]string, 0, len(presence))
	seen := make(map[string]struct{}, len(presence))
	for _, item := range presence {
		gatewayID := strings.TrimSpace(item.GatewayID)
		if gatewayID == "" {
			continue
		}
		if _, ok := seen[gatewayID]; ok {
			continue
		}
		seen[gatewayID] = struct{}{}
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
		"external_port":      float64(session.ExternalPort),
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
	streamID, err := util.GenerateID("gwstream")
	if err != nil {
		return nil
	}
	connection := &ControlConnection{
		registry:    registry,
		gatewayID:   strings.TrimSpace(gateway.ID),
		fqdn:        strings.TrimSpace(gateway.FQDN),
		endpoint:    strings.TrimSpace(endpoint),
		ownerID:     registry.instanceID + ":" + streamID,
		connectedAt: registry.now().UTC(),
		done:        make(chan struct{}),
	}
	registry.mu.Lock()
	if previous := registry.connections[connection.gatewayID]; previous != nil {
		previous.Close()
	}
	registry.connections[connection.gatewayID] = connection
	registry.mu.Unlock()
	if err := registry.saveConnectionState(context.Background(), connection); err != nil {
		connection.Close()
		return nil
	}
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
		if registry.runtime != nil {
			_ = registry.runtime.DeleteGatewayPresence(context.Background(), connection.gatewayID, connection.ownerID)
		}
	}
	registry.mu.Unlock()
}

func (registry *ControlRegistry) send(ctx context.Context, gatewayID string, command *structpb.Struct) error {
	if registry == nil || registry.runtime == nil {
		return ErrControlNotConnected
	}
	gatewayID = strings.TrimSpace(gatewayID)
	if gatewayID == "" {
		return errors.New("gateway_id is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	presence, ok, err := registry.runtime.GetGatewayPresence(ctx, gatewayID)
	if err != nil {
		return err
	}
	if !ok || strings.TrimSpace(presence.OwnerID) == "" {
		return fmt.Errorf("%w: %s", ErrControlNotConnected, gatewayID)
	}
	commandMap := command.AsMap()
	commandID, _ := commandMap["command_id"].(string)
	commandID = strings.TrimSpace(commandID)
	if commandID == "" {
		return errors.New("gateway control command_id is required")
	}
	raw, err := json.Marshal(commandMap)
	if err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().UTC().Add(30 * time.Second)
	}
	ttl := time.Until(deadline)
	if ttl <= 0 {
		return context.DeadlineExceeded
	}
	if err := registry.runtime.EnqueueGatewayCommand(ctx, gatewayID, presence.OwnerID, commandID, raw, ttl); err != nil {
		if errors.Is(err, redisstate.ErrGatewayControlNotConnected) || errors.Is(err, redisstate.ErrGatewayControlOwnerChanged) {
			return fmt.Errorf("%w: %s", ErrControlNotConnected, gatewayID)
		}
		return err
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		result, found, err := registry.runtime.GetGatewayCommandResult(ctx, commandID)
		if err != nil {
			return err
		}
		if found {
			if strings.TrimSpace(result.Error) != "" {
				return errors.New(result.Error)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
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
		default:
		}
		if err := connection.registry.saveConnectionState(ctx, connection); err != nil {
			return err
		}
		envelope, err := connection.registry.runtime.PopGatewayCommand(ctx, connection.gatewayID, connection.ownerID, 250*time.Millisecond)
		if errors.Is(err, redisstate.ErrGatewayControlOwnerChanged) {
			return ErrControlStreamReplaced
		}
		if err != nil {
			return err
		}
		if envelope == nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-connection.done:
				return ErrControlStreamReplaced
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		if err := connection.sendEnvelope(ctx, envelope, send); err != nil {
			return err
		}
	}
}

func (registry *ControlRegistry) saveConnectionState(ctx context.Context, connection *ControlConnection) error {
	if registry == nil || registry.runtime == nil || connection == nil {
		return nil
	}
	return registry.runtime.SetGatewayPresence(ctx, redisstate.GatewayPresence{
		GatewayID: connection.gatewayID,
		OwnerID:   connection.ownerID,
		Endpoint:  connection.endpoint,
	}, gatewayControlPresenceTTL)
}

func (connection *ControlConnection) sendEnvelope(ctx context.Context, envelope *redisstate.GatewayCommandEnvelope, send func(*structpb.Struct) error) error {
	if connection == nil || connection.registry == nil || connection.registry.runtime == nil || envelope == nil {
		return nil
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		_ = connection.registry.runtime.CompleteGatewayCommand(ctx, envelope.CommandID, err.Error(), gatewayControlResultTTL)
		return nil
	}
	command, err := structpb.NewStruct(payload)
	if err != nil {
		_ = connection.registry.runtime.CompleteGatewayCommand(ctx, envelope.CommandID, err.Error(), gatewayControlResultTTL)
		return nil
	}
	sendErr := send(command)
	errMessage := ""
	if sendErr != nil {
		errMessage = sendErr.Error()
	}
	if err := connection.registry.runtime.CompleteGatewayCommand(ctx, envelope.CommandID, errMessage, gatewayControlResultTTL); err != nil {
		return err
	}
	return nil
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
	if session.ExternalPort <= 0 {
		return errors.New("external_port must be positive")
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
