package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"agent/internal/service/enrollment"
	flowauthorization "agent/internal/service/flow-authorization"
	gatewaytunnel "agent/internal/service/gateway-tunnel"
	pdpclient "agent/internal/service/pdp-client"
	trafficinterception "agent/internal/service/traffic-interception"
	"agent/internal/service/usersession"
)

type flowAuthorizer interface {
	AuthorizeResource(context.Context, flowauthorization.AuthorizeRequest) (flowauthorization.AuthorizeResponse, error)
	Close() error
}

type resourceStreamConnectorConfig struct {
	PDPCAFile     string
	GatewayCAFile string
}

type authenticatedSessionProvider interface {
	ActiveAuthenticatedSession() (usersession.AuthenticatedSession, bool, error)
}

type enrollmentRecordProvider interface {
	Record(context.Context) (enrollment.EnrollmentRecord, error)
}

type resourceStreamConnector struct {
	logger         *slog.Logger
	config         resourceStreamConnectorConfig
	enrollment     enrollmentRecordProvider
	userSessions   authenticatedSessionProvider
	deviceIdentity enrollment.DeviceIdentity
	pdpClient      *pdpclient.Client

	mu                   sync.Mutex
	authorizer           flowAuthorizer
	authorizerThumbprint string
	tunnel               gatewayTunnel
}

func newResourceStreamConnector(config resourceStreamConnectorConfig, dependencies Dependencies, enrollmentManager *enrollment.Manager, userSessionManager *usersession.Manager, deviceIdentity enrollment.DeviceIdentity, pdpClient *pdpclient.Client) *resourceStreamConnector {
	logger := dependencies.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if deviceIdentity == nil {
		deviceIdentity = enrollment.NewDefaultDeviceIdentity()
	}
	connector := &resourceStreamConnector{
		logger:         logger,
		config:         config,
		enrollment:     enrollmentManager,
		userSessions:   userSessionManager,
		deviceIdentity: deviceIdentity,
		pdpClient:      pdpClient,
		authorizer:     dependencies.FlowAuthorizer,
		tunnel:         dependencies.GatewayTunnel,
	}
	return connector
}

func (connector *resourceStreamConnector) OpenResourceStream(ctx context.Context, request trafficinterception.StreamRequest) (net.Conn, error) {
	if connector == nil {
		return nil, fmt.Errorf("resource stream connector is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	session, found, err := connector.userSessions.ActiveAuthenticatedSession()
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("resource access requires an authenticated user session")
	}
	record, err := connector.enrollment.Record(ctx)
	if err != nil {
		return nil, fmt.Errorf("load enrollment record: %w", err)
	}
	authorizer, err := connector.authorizerFor(ctx, record)
	if err != nil {
		return nil, err
	}
	protocol := normalizedProtocol(request.Protocol)
	port := request.Port
	authorization, err := authorizer.AuthorizeResource(ctx, flowauthorization.AuthorizeRequest{
		AgentSessionToken: session.AgentSessionToken,
		ResourceID:        request.ResourceID,
		Protocol:          protocol,
		Port:              port,
	})
	if err != nil {
		return nil, fmt.Errorf("authorize resource %s: %w", request.ResourceID, err)
	}
	if !strings.EqualFold(strings.TrimSpace(authorization.Decision), flowauthorization.DecisionAllow) {
		decision := strings.TrimSpace(authorization.Decision)
		if decision == "" {
			decision = "deny"
		}
		reason := strings.TrimSpace(authorization.Reason)
		if reason == "" {
			reason = "policy decision did not allow the flow"
		}
		return nil, fmt.Errorf("resource access %s: %s", decision, reason)
	}
	if strings.TrimSpace(authorization.SessionID) == "" || strings.TrimSpace(authorization.SessionToken) == "" {
		return nil, fmt.Errorf("PDP allowed resource %s without Gateway session material", request.ResourceID)
	}
	gatewayEndpoint := firstNonEmpty(authorization.GatewayEndpoint, record.GatewayEndpoints...)
	if gatewayEndpoint == "" {
		return nil, fmt.Errorf("PDP allowed resource %s without gateway endpoint", request.ResourceID)
	}
	tunnel, err := connector.gatewayTunnel()
	if err != nil {
		return nil, err
	}
	return tunnel.OpenResourceStream(ctx, gatewaytunnel.ResourceStreamRequest{
		TargetHost:      firstNonEmpty(request.SyntheticIP, request.FQDN),
		TargetPort:      port,
		SessionID:       authorization.SessionID,
		SessionToken:    authorization.SessionToken,
		ResourceID:      firstNonEmpty(authorization.ResourceID, request.ResourceID),
		Protocol:        protocol,
		GatewayID:       authorization.GatewayID,
		GatewayEndpoint: gatewayEndpoint,
	})
}

func (connector *resourceStreamConnector) authorizerFor(ctx context.Context, record enrollment.EnrollmentRecord) (flowAuthorizer, error) {
	connector.mu.Lock()
	defer connector.mu.Unlock()
	thumbprint := strings.TrimSpace(record.DeviceCertThumbprint)
	if connector.authorizer != nil && (connector.authorizerThumbprint == "" || connector.authorizerThumbprint == thumbprint) {
		return connector.authorizer, nil
	}
	if connector.authorizer != nil {
		_ = connector.authorizer.Close()
		connector.authorizer = nil
	}
	client, err := flowAuthorizationClientFromPDP(ctx, connector.pdpClient, record)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, fmt.Errorf("shared PDP gRPC client is required for flow authorization")
	}
	connector.authorizer = client
	connector.authorizerThumbprint = thumbprint
	return connector.authorizer, nil
}

func (connector *resourceStreamConnector) gatewayTunnel() (gatewayTunnel, error) {
	connector.mu.Lock()
	defer connector.mu.Unlock()
	if connector.tunnel != nil {
		return connector.tunnel, nil
	}
	tunnel, err := gatewaytunnel.NewManager(gatewaytunnel.Options{
		Enabled: true,
		CAFile:  firstNonEmpty(connector.config.GatewayCAFile, connector.config.PDPCAFile),
		ClientCertificateProvider: func(ctx context.Context) (tls.Certificate, error) {
			record, err := connector.enrollment.Record(ctx)
			if err != nil {
				return tls.Certificate{}, err
			}
			certificate, _, err := connector.deviceIdentity.ClientCertificate(ctx, record)
			return certificate, err
		},
		DeviceIDProvider: func() string {
			record, err := connector.enrollment.Record(context.Background())
			if err != nil {
				return ""
			}
			return strings.TrimSpace(record.DeviceID)
		},
		Logger: connector.logger,
	})
	if err != nil {
		return nil, err
	}
	connector.tunnel = tunnel
	return connector.tunnel, nil
}

func normalizedProtocol(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "http", "https", "tcp":
		return "tcp"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func firstNonEmpty(value string, values ...string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	for _, candidate := range values {
		if strings.TrimSpace(candidate) != "" {
			return strings.TrimSpace(candidate)
		}
	}
	return ""
}
