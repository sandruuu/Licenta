package usersession

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"agent/internal/service/enrollment"
	"agent/internal/shared/ipc"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	sessionGRPCServiceName       = "trustagent.session.AgentSessionService"
	sessionGRPCStartSessionPath  = "/" + sessionGRPCServiceName + "/StartSession"
	sessionGRPCSessionStatusPath = "/" + sessionGRPCServiceName + "/SessionStatus"
	sessionGRPCClaimSessionPath  = "/" + sessionGRPCServiceName + "/ClaimSession"
	sessionGRPCGetCatalogPath    = "/" + sessionGRPCServiceName + "/GetCatalog"
	sessionGRPCRevokeSessionPath = "/" + sessionGRPCServiceName + "/RevokeSession"
)

type GRPCClient struct {
	connection *grpc.ClientConn
	cleanup    func()
}

func (manager *Manager) ensureClient(ctx context.Context, record enrollment.EnrollmentRecord) (Client, error) {
	manager.mu.RLock()
	client := manager.client
	manager.mu.RUnlock()
	if client != nil {
		return client, nil
	}
	if manager.deviceIdentity == nil {
		manager.deviceIdentity = enrollment.NewDefaultDeviceIdentity()
	}
	client, err := NewGRPCClient(ctx, manager.config, record, manager.deviceIdentity)
	if err != nil {
		return nil, err
	}
	manager.mu.Lock()
	if manager.client == nil {
		manager.client = client
	} else {
		_ = client.Close()
		client = manager.client
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

func NewGRPCClient(ctx context.Context, config Config, record enrollment.EnrollmentRecord, identity enrollment.DeviceIdentity) (*GRPCClient, error) {
	target := strings.TrimSpace(config.PDPGRPCEndpoint)
	if target == "" {
		return nil, fmt.Errorf("pdp_grpc_endpoint is required for user session")
	}
	certificate, cleanup, err := identity.ClientCertificate(ctx, record)
	if err != nil {
		return nil, fmt.Errorf("load device client certificate: %w", err)
	}
	tlsConfig, err := sessionTLSConfig(config, certificate)
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, err
	}
	connection, err := grpc.NewClient(target, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, fmt.Errorf("create PDP session gRPC client: %w", err)
	}
	return &GRPCClient{connection: connection, cleanup: cleanup}, nil
}

func sessionTLSConfig(config Config, certificate tls.Certificate) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		ServerName:   strings.TrimSpace(config.PDPTLSServerName),
		Certificates: []tls.Certificate{certificate},
	}
	if strings.TrimSpace(config.PDPCAFile) == "" {
		return tlsConfig, nil
	}
	caPEM, err := os.ReadFile(strings.TrimSpace(config.PDPCAFile))
	if err != nil {
		return nil, fmt.Errorf("read pdp_ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("pdp_ca_file contains no certificates")
	}
	tlsConfig.RootCAs = pool
	return tlsConfig, nil
}

func (client *GRPCClient) StartSession(ctx context.Context, request StartSessionRequest) (StartSessionResponse, error) {
	payload, err := structpb.NewStruct(map[string]any{
		"device_id":              request.DeviceID,
		"agent_version":          request.AgentVersion,
		"device_cert_thumbprint": request.DeviceCertThumbprint,
		"device_data_revision":   request.DeviceDataRevision,
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
		PollInterval:     secondsField(fields, "poll_interval_seconds"),
		Status:           stringField(fields, "status"),
	}, nil
}

func (client *GRPCClient) SessionStatus(ctx context.Context, request SessionStatusRequest) (SessionStatusResponse, error) {
	payload, err := structpb.NewStruct(map[string]any{
		"session_request_id": request.SessionRequestID,
		"claim_secret":       request.ClaimSecret,
	})
	if err != nil {
		return SessionStatusResponse{}, err
	}
	var response structpb.Struct
	if err := client.connection.Invoke(ctx, sessionGRPCSessionStatusPath, payload, &response); err != nil {
		return SessionStatusResponse{}, err
	}
	fields := response.AsMap()
	return SessionStatusResponse{Status: stringField(fields, "status"), Reason: stringField(fields, "reason", "message")}, nil
}

func (client *GRPCClient) ClaimSession(ctx context.Context, request ClaimSessionRequest) (ClaimSessionResponse, error) {
	payload, err := structpb.NewStruct(map[string]any{
		"session_request_id":   request.SessionRequestID,
		"claim_secret":         request.ClaimSecret,
		"device_data_revision": request.DeviceDataRevision,
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
		Version:     stringField(fields, "version"),
		DNSSuffixes: stringListField(fields["dns_suffixes"]),
		Resources:   catalogResources(fields["resources"]),
		TTLSeconds:  int(numberField(fields, "ttl_seconds")),
		PolicyEpoch: stringField(fields, "policy_epoch"),
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
	if client == nil {
		return nil
	}
	if client.cleanup != nil {
		client.cleanup()
		client.cleanup = nil
	}
	if client.connection != nil {
		return client.connection.Close()
	}
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

func secondsField(fields map[string]any, name string) time.Duration {
	value := numberField(fields, name)
	if value <= 0 {
		return 0
	}
	return time.Duration(value * float64(time.Second))
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
			DisplayName: stringField(entry, "display_name", "resource_id"),
			FQDN:        stringField(entry, "fqdn"),
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

func stringListField(value any) []string {
	raw, ok := value.([]any)
	if !ok {
		return nil
	}
	values := make([]string, 0, len(raw))
	for _, item := range raw {
		text := strings.TrimSpace(fmt.Sprint(item))
		if text != "" {
			values = append(values, text)
		}
	}
	return values
}
