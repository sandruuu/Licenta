package usersession

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"agent/internal/service/enrollment"
	"agent/internal/shared/ipc"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	sessionGRPCServiceName       = "trustagent.session.AgentSessionService"
	sessionGRPCStartSessionPath  = "/" + sessionGRPCServiceName + "/StartSession"
	sessionGRPCWatchStatusPath   = "/" + sessionGRPCServiceName + "/WatchSessionStatus"
	sessionGRPCClaimSessionPath  = "/" + sessionGRPCServiceName + "/ClaimSession"
	sessionGRPCGetCatalogPath    = "/" + sessionGRPCServiceName + "/GetCatalog"
	sessionGRPCRenewSessionPath  = "/" + sessionGRPCServiceName + "/RenewSession"
	sessionGRPCRevokeSessionPath = "/" + sessionGRPCServiceName + "/RevokeSession"
)

type GRPCClient struct {
	connection *grpc.ClientConn
}

func (manager *Manager) ensureClient(ctx context.Context, record enrollment.EnrollmentRecord) (Client, error) {
	deviceID := strings.TrimSpace(record.DeviceID)
	thumbprint := strings.TrimSpace(record.DeviceCertThumbprint)
	manager.mu.RLock()
	client := manager.client
	if client != nil && (manager.clientDeviceID == "" || (manager.clientDeviceID == deviceID && manager.clientThumbprint == thumbprint)) {
		manager.mu.RUnlock()
		return client, nil
	}
	manager.mu.RUnlock()
	factory := manager.clientFactory
	if factory == nil {
		return nil, fmt.Errorf("shared PDP gRPC client factory is required for user session")
	}
	client, err := factory(ctx, manager.config, record)
	if err != nil {
		return nil, err
	}
	manager.mu.Lock()
	if manager.client == nil {
		manager.client = client
		manager.clientDeviceID = deviceID
		manager.clientThumbprint = thumbprint
	} else {
		if manager.clientDeviceID == "" || (manager.clientDeviceID == deviceID && manager.clientThumbprint == thumbprint) {
			_ = client.Close()
			client = manager.client
		} else {
			_ = manager.client.Close()
			manager.client = client
			manager.clientDeviceID = deviceID
			manager.clientThumbprint = thumbprint
		}
	}
	manager.mu.Unlock()
	return client, nil
}

func (manager *Manager) clientForLogout(ctx context.Context) (Client, error) {
	manager.mu.RLock()
	client := manager.client
	manager.mu.RUnlock()
	if client != nil {
		return client, nil
	}
	if manager.enrollment == nil {
		return nil, fmt.Errorf("enrollment provider is unavailable")
	}
	record, err := manager.enrollment.Record(ctx)
	if err != nil {
		return nil, err
	}
	return manager.ensureClient(ctx, record)
}

func NewGRPCClientFromConnection(connection *grpc.ClientConn) (*GRPCClient, error) {
	if connection == nil {
		return nil, fmt.Errorf("PDP gRPC connection is required for user session")
	}
	return &GRPCClient{connection: connection}, nil
}

func (client *GRPCClient) StartSession(ctx context.Context, request StartSessionRequest) (StartSessionResponse, error) {
	payload, err := structpb.NewStruct(map[string]any{
		"device_id":                request.DeviceID,
		"agent_version":            request.AgentVersion,
		"device_cert_thumbprint":   request.DeviceCertThumbprint,
		"device_data_revision":     request.DeviceDataRevision,
		"session_renewal_required": true,
		"local_user": map[string]any{
			"sid_hash":                 request.LocalUserSIDHash,
			"windows_logon_session_id": request.WindowsLogonSessionID,
			"windows_session_id":       request.WindowsSessionID,
		},
	})
	if err != nil {
		return StartSessionResponse{}, err
	}
	var response structpb.Struct
	if err := client.connection.Invoke(ctx, sessionGRPCStartSessionPath, payload, &response); err != nil {
		return StartSessionResponse{}, err
	}
	fields := response.AsMap()
	return StartSessionResponse{
		SessionRequestID: stringField(fields, "session_request_id"),
		AuthURL:          stringField(fields, "auth_url"),
		ClaimSecret:      stringField(fields, "claim_secret"),
		ExpiresAt:        timeField(fields, "expires_at"),
		Status:           stringField(fields, "status"),
	}, nil
}

func (client *GRPCClient) WatchSessionStatus(ctx context.Context, request SessionStatusRequest, handler func(SessionStatusResponse) bool) error {
	if handler == nil {
		return fmt.Errorf("session status handler is required")
	}
	payload, err := structpb.NewStruct(map[string]any{
		"session_request_id": request.SessionRequestID,
		"claim_secret":       request.ClaimSecret,
	})
	if err != nil {
		return err
	}
	stream, err := client.connection.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, sessionGRPCWatchStatusPath)
	if err != nil {
		return err
	}
	if err := stream.SendMsg(payload); err != nil {
		return err
	}
	if err := stream.CloseSend(); err != nil {
		return err
	}
	for {
		message := &structpb.Struct{}
		if err := stream.RecvMsg(message); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		fields := message.AsMap()
		if !handler(SessionStatusResponse{Status: stringField(fields, "status"), Reason: stringField(fields, "reason", "message")}) {
			return nil
		}
	}
}

func (client *GRPCClient) ClaimSession(ctx context.Context, request ClaimSessionRequest) (ClaimSessionResponse, error) {
	payload, err := structpb.NewStruct(map[string]any{
		"session_request_id":       request.SessionRequestID,
		"claim_secret":             request.ClaimSecret,
		"device_data_revision":     request.DeviceDataRevision,
		"session_renewal_required": true,
		"local_user": map[string]any{
			"sid_hash":                 request.LocalUserSIDHash,
			"windows_logon_session_id": request.WindowsLogonSessionID,
			"windows_session_id":       request.WindowsSessionID,
		},
	})
	if err != nil {
		return ClaimSessionResponse{}, err
	}
	var response structpb.Struct
	if err := client.connection.Invoke(ctx, sessionGRPCClaimSessionPath, payload, &response); err != nil {
		return ClaimSessionResponse{}, err
	}
	fields := response.AsMap()
	user := mapField(fields, "user")
	return ClaimSessionResponse{
		AgentSessionID:    stringField(fields, "agent_session_id"),
		AgentSessionToken: stringField(fields, "agent_session_token"),
		ExpiresAt:         timeField(fields, "expires_at"),
		PolicyEpoch:       int(numberField(fields, "policy_epoch")),
		DisplayName:       stringField(user, "display_name", "email"),
		Email:             stringField(user, "email"),
	}, nil
}

func (client *GRPCClient) GetCatalog(ctx context.Context, request GetCatalogRequest) (CatalogResponse, error) {
	payload, err := structpb.NewStruct(map[string]any{
		"access_token":    request.AgentSessionToken,
		"current_version": request.CurrentVersion,
	})
	if err != nil {
		return CatalogResponse{}, err
	}
	var response structpb.Struct
	if err := client.connection.Invoke(ctx, sessionGRPCGetCatalogPath, payload, &response); err != nil {
		return CatalogResponse{}, err
	}
	fields := response.AsMap()
	return CatalogResponse{
		Version:          stringField(fields, "version"),
		Resources:        catalogResources(fields["resources"]),
		TTLSeconds:       int(numberField(fields, "ttl_seconds")),
		PolicyEpoch:      stringField(fields, "policy_epoch"),
		DeviceDataPolicy: deviceDataPolicy(fields["device_data_policy"]),
	}, nil
}

func (client *GRPCClient) RenewSession(ctx context.Context, request RenewSessionRequest) (RenewSessionResponse, error) {
	payload, err := structpb.NewStruct(map[string]any{
		"access_token": request.AgentSessionToken,
		"session_id":   request.SessionID,
	})
	if err != nil {
		return RenewSessionResponse{}, err
	}
	var response structpb.Struct
	if err := client.connection.Invoke(ctx, sessionGRPCRenewSessionPath, payload, &response); err != nil {
		return RenewSessionResponse{}, err
	}
	fields := response.AsMap()
	return RenewSessionResponse{
		AgentSessionID:    stringField(fields, "agent_session_id"),
		AgentSessionToken: stringField(fields, "agent_session_token"),
		ExpiresAt:         timeField(fields, "expires_at"),
		IdleExpiresAt:     timeField(fields, "idle_expires_at"),
		AbsoluteExpiresAt: timeField(fields, "absolute_expires_at"),
		PolicyEpoch:       int(numberField(fields, "policy_epoch")),
	}, nil
}

func (client *GRPCClient) RevokeSession(ctx context.Context, request RevokeSessionRequest) error {
	payload, err := structpb.NewStruct(map[string]any{
		"access_token": request.AgentSessionToken,
		"session_id":   request.SessionID,
	})
	if err != nil {
		return err
	}
	var response structpb.Struct
	return client.connection.Invoke(ctx, sessionGRPCRevokeSessionPath, payload, &response)
}

func (client *GRPCClient) Close() error {
	return nil
}

func stringField(fields map[string]any, names ...string) string {
	for _, name := range names {
		if value, ok := fields[name]; ok {
			return strings.TrimSpace(fmt.Sprint(value))
		}
	}
	return ""
}

func numberField(fields map[string]any, name string) float64 {
	value, ok := fields[name]
	if !ok {
		return 0
	}
	switch typed := value.(type) {
	case float64:
		return typed
	case int:
		return float64(typed)
	case string:
		parsed, _ := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		return parsed
	default:
		return 0
	}
}

func mapField(fields map[string]any, name string) map[string]any {
	value, ok := fields[name]
	if !ok || value == nil {
		return nil
	}
	if typed, ok := value.(map[string]any); ok {
		return typed
	}
	return nil
}

func timeField(fields map[string]any, name string) time.Time {
	value := stringField(fields, name)
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}

func catalogResources(value any) []ipc.CatalogResource {
	raw, ok := value.([]any)
	if !ok {
		return nil
	}
	resources := make([]ipc.CatalogResource, 0, len(raw))
	for _, item := range raw {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		resource := ipc.CatalogResource{
			ResourceID:  stringField(entry, "resource_id"),
			DisplayName: stringField(entry, "display_name"),
			FQDN:        stringField(entry, "fqdn"),
			Type:        stringField(entry, "type"),
			Protocol:    stringField(entry, "protocol"),
			Port:        int(numberField(entry, "port")),
			AccessMode:  stringField(entry, "access_mode", "protocol"),
		}
		if resource.ResourceID != "" || resource.FQDN != "" {
			resources = append(resources, resource)
		}
	}
	return resources
}

func deviceDataPolicy(value any) ipc.DeviceDataPolicy {
	fields, ok := value.(map[string]any)
	if !ok {
		return ipc.DeviceDataPolicy{}
	}
	return ipc.DeviceDataPolicy{
		RequiredChecks:      stringSliceField(fields["required_checks"]),
		RequiredCheckStatus: stringField(fields, "required_check_status"),
	}
}

func stringSliceField(value any) []string {
	raw, ok := value.([]any)
	if !ok {
		return nil
	}
	values := make([]string, 0, len(raw))
	for _, item := range raw {
		if text := strings.TrimSpace(fmt.Sprint(item)); text != "" {
			values = append(values, text)
		}
	}
	return values
}
