package authz

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"ztna.local/agent/internal/relay"
	"ztna.local/agent/internal/tunnel"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/structpb"
)

const agentAuthorizationGRPCAuthorizePath = "/ztna.agent.v1.AgentAuthorizationService/AuthorizeResource"

type ClientCertificateProvider func(context.Context) (tls.Certificate, error)

type AccessTokenProvider func() (accessToken, deviceID string)

type Config struct {
	CloudURL                  string
	CAFile                    string
	ClientCertificateProvider ClientCertificateProvider
	AccessTokenProvider       AccessTokenProvider
	Timeout                   time.Duration
	DialOptions               []grpc.DialOption
}

type Client struct {
	cloudURL                  string
	caFile                    string
	clientCertificateProvider ClientCertificateProvider
	accessTokenProvider       AccessTokenProvider
	timeout                   time.Duration
	dialOptions               []grpc.DialOption
}

type DecisionError struct {
	Decision    string
	Reason      string
	RiskScore   int
	MatchedRule string
}

func (err *DecisionError) Error() string {
	if err == nil {
		return "authorization failed"
	}
	decision := strings.TrimSpace(err.Decision)
	if decision == "" {
		decision = "deny"
	}
	reason := strings.TrimSpace(err.Reason)
	if reason == "" {
		reason = "policy administrator denied resource access"
	}
	return fmt.Sprintf("%s: %s", decision, reason)
}

func (err *DecisionError) ErrorCode() string {
	if err == nil || strings.TrimSpace(err.Decision) == "" {
		return "authorization_failed"
	}
	return strings.TrimSpace(err.Decision)
}

func NewClient(config Config) (*Client, error) {
	cloudURL := strings.TrimRight(strings.TrimSpace(config.CloudURL), "/")
	if cloudURL == "" {
		return nil, errors.New("cloud URL is required")
	}
	if config.ClientCertificateProvider == nil {
		return nil, errors.New("client certificate provider is required")
	}
	if config.AccessTokenProvider == nil {
		return nil, errors.New("access token provider is required")
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Client{
		cloudURL:                  cloudURL,
		caFile:                    strings.TrimSpace(config.CAFile),
		clientCertificateProvider: config.ClientCertificateProvider,
		accessTokenProvider:       config.AccessTokenProvider,
		timeout:                   timeout,
		dialOptions:               append([]grpc.DialOption(nil), config.DialOptions...),
	}, nil
}

func (client *Client) AuthorizeResource(ctx context.Context, request relay.ResourceAuthorizationRequest) (relay.ResourceAuthorizationResult, error) {
	if client == nil {
		return relay.ResourceAuthorizationResult{}, errors.New("authorization client is nil")
	}
	accessToken, deviceID := client.accessTokenProvider()
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return relay.ResourceAuthorizationResult{}, errors.New("access token is required")
	}
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return relay.ResourceAuthorizationResult{}, errors.New("device ID is required")
	}
	resourceID := strings.TrimSpace(request.ResourceID)
	if resourceID == "" {
		return relay.ResourceAuthorizationResult{}, errors.New("resource ID is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	grpcRequest, err := authorizationRequestStruct(request)
	if err != nil {
		return relay.ResourceAuthorizationResult{}, fmt.Errorf("build authorization gRPC request: %w", err)
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+accessToken)
	var response structpb.Struct
	if err := client.invoke(ctx, agentAuthorizationGRPCAuthorizePath, grpcRequest, &response); err != nil {
		return relay.ResourceAuthorizationResult{}, err
	}
	return authorizationResultFromStruct(&response)
}

func (client *Client) invoke(ctx context.Context, method string, request *structpb.Struct, response *structpb.Struct) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, client.timeout)
		defer cancel()
	}
	clientCertificate, err := client.clientCertificateProvider(ctx)
	if err != nil {
		return fmt.Errorf("load authorization gRPC mTLS credential: %w", err)
	}
	target, serverName, err := grpcTargetFromCloudURL(client.cloudURL)
	if err != nil {
		return err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{clientCertificate}}
	if serverName != "" {
		tlsConfig.ServerName = serverName
	}
	if client.caFile != "" {
		pool, err := rootCAPool(client.caFile)
		if err != nil {
			return err
		}
		tlsConfig.RootCAs = pool
	}
	dialOptions := []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))}
	dialOptions = append(dialOptions, client.dialOptions...)
	conn, err := grpc.DialContext(ctx, target, dialOptions...)
	if err != nil {
		return fmt.Errorf("dial authorization gRPC endpoint: %w", err)
	}
	defer conn.Close()
	if err := conn.Invoke(ctx, method, request, response); err != nil {
		return fmt.Errorf("invoke authorization gRPC method %s: %w", method, err)
	}
	return nil
}

func authorizationRequestStruct(request relay.ResourceAuthorizationRequest) (*structpb.Struct, error) {
	payload := map[string]interface{}{
		"resource_id": strings.TrimSpace(request.ResourceID),
		"protocol":    strings.TrimSpace(request.Protocol),
	}
	if request.Port > 0 {
		payload["port"] = float64(request.Port)
	}
	if process := processIdentityMap(request.Process); process != nil {
		payload["process"] = process
	}
	return structpb.NewStruct(payload)
}

func processIdentityMap(process *tunnel.ProcessIdentity) map[string]interface{} {
	if process == nil {
		return nil
	}
	payload := make(map[string]interface{}, 5)
	if process.PID > 0 {
		payload["pid"] = float64(process.PID)
	}
	if strings.TrimSpace(process.Name) != "" {
		payload["name"] = strings.TrimSpace(process.Name)
	}
	if strings.TrimSpace(process.Path) != "" {
		payload["path"] = strings.TrimSpace(process.Path)
	}
	if strings.TrimSpace(process.SHA256) != "" {
		payload["sha256"] = strings.TrimSpace(process.SHA256)
	}
	if strings.TrimSpace(process.Signer) != "" {
		payload["signer"] = strings.TrimSpace(process.Signer)
	}
	if len(payload) == 0 {
		return nil
	}
	return payload
}

func authorizationResultFromStruct(response *structpb.Struct) (relay.ResourceAuthorizationResult, error) {
	decision := strings.TrimSpace(structFieldString(response, "decision"))
	if decision == "" {
		return relay.ResourceAuthorizationResult{}, errors.New("authorization response decision is required")
	}
	if decision != "allow" {
		return relay.ResourceAuthorizationResult{}, &DecisionError{Decision: decision, Reason: strings.TrimSpace(structFieldString(response, "reason")), RiskScore: int(structFieldNumberDefault(response, "risk_score")), MatchedRule: strings.TrimSpace(structFieldString(response, "matched_rule"))}
	}
	result := relay.ResourceAuthorizationResult{
		SessionID:       strings.TrimSpace(structFieldString(response, "session_id")),
		SessionToken:    strings.TrimSpace(structFieldString(response, "session_token")),
		ResourceID:      strings.TrimSpace(structFieldString(response, "resource_id")),
		Protocol:        strings.TrimSpace(structFieldString(response, "protocol")),
		Port:            int(structFieldNumberDefault(response, "port")),
		GatewayID:       strings.TrimSpace(structFieldString(response, "gateway_id")),
		GatewayEndpoint: strings.TrimSpace(structFieldString(response, "gateway_endpoint")),
	}
	if result.SessionID == "" || result.SessionToken == "" || result.ResourceID == "" {
		return relay.ResourceAuthorizationResult{}, errors.New("authorization response is missing strict session material")
	}
	if expiresAt := strings.TrimSpace(structFieldString(response, "expires_at")); expiresAt != "" {
		parsed, err := time.Parse(time.RFC3339Nano, expiresAt)
		if err != nil {
			return relay.ResourceAuthorizationResult{}, fmt.Errorf("parse authorization expiry: %w", err)
		}
		result.ExpiresAt = parsed.UTC()
	}
	return result, nil
}

func rootCAPool(caFile string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("CA file does not contain PEM certificates")
	}
	return pool, nil
}

func grpcTargetFromCloudURL(raw string) (string, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", fmt.Errorf("parse cloud URL: %w", err)
	}
	host := parsed.Host
	if host == "" && parsed.Scheme == "" && parsed.Path != "" {
		host = parsed.Path
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", "", errors.New("cloud URL host is required")
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443")
	}
	serverName := parsed.Hostname()
	if serverName == "" {
		if splitHost, _, err := net.SplitHostPort(host); err == nil {
			serverName = splitHost
		}
	}
	return host, serverName, nil
}

func structFieldString(value *structpb.Struct, key string) string {
	if value == nil {
		return ""
	}
	field, ok := value.GetFields()[key]
	if !ok || field == nil {
		return ""
	}
	return field.GetStringValue()
}

func structFieldNumberDefault(value *structpb.Struct, key string) float64 {
	if value == nil {
		return 0
	}
	field, ok := value.GetFields()[key]
	if !ok || field == nil {
		return 0
	}
	return field.GetNumberValue()
}
