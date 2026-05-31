package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"agent/internal/service/enrollment"
	flowauthorization "agent/internal/service/flow-authorization"
	gatewaytunnel "agent/internal/service/gateway-tunnel"
	pdpclient "agent/internal/service/pdp-client"
	trafficinterception "agent/internal/service/traffic-interception"
	"agent/internal/service/usersession"
)

var ErrAuthenticationRequired = errors.New("resource access requires an authenticated user session")
var ErrStepUpRequired = errors.New("resource access requires additional verification")

type flowAuthorizer interface {
	AuthorizeResource(context.Context, flowauthorization.AuthorizeRequest) (flowauthorization.AuthorizeResponse, error)
	Close() error
}

type resourceStreamConnectorConfig struct {
	PDPCAFile     string
	GatewayCAFile string
}

const (
	resourceSessionRenewBefore  = time.Minute
	resourceSessionRenewTimeout = 15 * time.Second
	resourceSessionMinRenewWait = 5 * time.Second
)

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

	mu                       sync.Mutex
	authorizer               flowAuthorizer
	authorizerThumbprint     string
	tunnel                   gatewayTunnel
	resourceSessions         map[resourceSessionCacheKey]flowauthorization.AuthorizeResponse
	onAuthenticationRequired func(trafficinterception.StreamRequest)
	onStepUpRequired         func(trafficinterception.StreamRequest, flowauthorization.AuthorizeResponse)
	onResourceAllowed        func(trafficinterception.StreamRequest, flowauthorization.AuthorizeResponse)
}

type resourceSessionCacheKey struct {
	AgentSessionID string
	ResourceID     string
	Protocol       string
	Port           int
	ProcessKey     string
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
		connector.recordAuthenticationRequired(request)
		return nil, fmt.Errorf("%w: sign in required to access protected resources", ErrAuthenticationRequired)
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
	processKey := resourceSessionProcessKey(request.Process)
	authorizationProcess := flowAuthorizationProcess(request.Process)
	gatewayProcess := gatewayTunnelProcess(request.Process)
	cacheKey := resourceSessionCacheKey{
		AgentSessionID: strings.TrimSpace(session.AgentSessionID),
		ResourceID:     strings.TrimSpace(request.ResourceID),
		Protocol:       protocol,
		Port:           port,
		ProcessKey:     processKey,
	}
	authRequest := flowauthorization.AuthorizeRequest{
		AgentSessionToken: session.AgentSessionToken,
		ResourceID:        request.ResourceID,
		Protocol:          protocol,
		Port:              port,
		Process:           authorizationProcess,
	}
	authorization, fromCache, err := connector.authorizeResourceSession(ctx, cacheKey, authorizer, authRequest, false)
	if err != nil {
		return nil, fmt.Errorf("authorize resource %s: %w", request.ResourceID, err)
	}
	if isStepUpRequired(authorization) {
		connector.recordStepUpRequired(request, authorization)
		return nil, fmt.Errorf("%w: %s", ErrStepUpRequired, firstNonEmpty(authorization.Reason, "additional verification required"))
	}
	if err := validateAllowedResourceAuthorization(request.ResourceID, authorization); err != nil {
		return nil, err
	}
	connector.recordResourceAllowed(request, authorization)
	gatewayEndpoint := firstNonEmpty(authorization.GatewayEndpoint, record.GatewayEndpoints...)
	if gatewayEndpoint == "" {
		return nil, fmt.Errorf("PDP allowed resource %s without gateway endpoint", request.ResourceID)
	}
	tunnel, err := connector.gatewayTunnel()
	if err != nil {
		return nil, err
	}
	streamRequest := gatewaytunnel.ResourceStreamRequest{
		TargetHost:        firstNonEmpty(request.SyntheticIP, request.FQDN),
		TargetPort:        port,
		SessionID:         authorization.SessionID,
		SessionToken:      authorization.SessionToken,
		ResourceID:        firstNonEmpty(authorization.ResourceID, request.ResourceID),
		Protocol:          protocol,
		GatewayID:         authorization.GatewayID,
		GatewayEndpoint:   gatewayEndpoint,
		GatewayServerName: authorization.GatewayServerName,
		Process:           gatewayProcess,
	}
	stream, err := tunnel.OpenResourceStream(ctx, streamRequest)
	if err != nil && fromCache && isRetryableGatewaySessionError(err) {
		connector.forgetResourceSession(cacheKey)
		authorization, _, err = connector.authorizeResourceSession(ctx, cacheKey, authorizer, authRequest, true)
		if err != nil {
			return nil, fmt.Errorf("reauthorize resource %s: %w", request.ResourceID, err)
		}
		if isStepUpRequired(authorization) {
			connector.recordStepUpRequired(request, authorization)
			return nil, fmt.Errorf("%w: %s", ErrStepUpRequired, firstNonEmpty(authorization.Reason, "additional verification required"))
		}
		if err := validateAllowedResourceAuthorization(request.ResourceID, authorization); err != nil {
			return nil, err
		}
		connector.recordResourceAllowed(request, authorization)
		streamRequest.SessionID = authorization.SessionID
		streamRequest.SessionToken = authorization.SessionToken
		streamRequest.ResourceID = firstNonEmpty(authorization.ResourceID, request.ResourceID)
		streamRequest.GatewayID = authorization.GatewayID
		streamRequest.GatewayEndpoint = firstNonEmpty(authorization.GatewayEndpoint, record.GatewayEndpoints...)
		streamRequest.GatewayServerName = authorization.GatewayServerName
		stream, err = tunnel.OpenResourceStream(ctx, streamRequest)
	}
	if err != nil {
		return nil, err
	}
	return connector.withResourceSessionRenewal(stream, cacheKey, authorizer, authRequest, authorization), nil
}

func (connector *resourceStreamConnector) authorizeResourceSession(ctx context.Context, key resourceSessionCacheKey, authorizer flowAuthorizer, request flowauthorization.AuthorizeRequest, force bool) (flowauthorization.AuthorizeResponse, bool, error) {
	if connector == nil {
		return flowauthorization.AuthorizeResponse{}, false, fmt.Errorf("resource stream connector is not configured")
	}
	if !force {
		if cached, ok := connector.cachedResourceSession(key); ok {
			return cached, true, nil
		}
	}
	authorization, err := authorizer.AuthorizeResource(ctx, request)
	if err != nil {
		return flowauthorization.AuthorizeResponse{}, false, err
	}
	if strings.EqualFold(strings.TrimSpace(authorization.Decision), flowauthorization.DecisionAllow) {
		connector.rememberResourceSession(key, authorization)
	}
	return authorization, false, nil
}

func (connector *resourceStreamConnector) cachedResourceSession(key resourceSessionCacheKey) (flowauthorization.AuthorizeResponse, bool) {
	if connector == nil || !key.cacheable() {
		return flowauthorization.AuthorizeResponse{}, false
	}
	connector.mu.Lock()
	defer connector.mu.Unlock()
	if connector.resourceSessions == nil {
		return flowauthorization.AuthorizeResponse{}, false
	}
	session, ok := connector.resourceSessions[key]
	if !ok {
		return flowauthorization.AuthorizeResponse{}, false
	}
	if !resourceSessionUsable(session, time.Now().Add(resourceSessionRenewBefore)) {
		delete(connector.resourceSessions, key)
		return flowauthorization.AuthorizeResponse{}, false
	}
	return session, true
}

func (connector *resourceStreamConnector) rememberResourceSession(key resourceSessionCacheKey, session flowauthorization.AuthorizeResponse) {
	if connector == nil || !key.cacheable() || !resourceSessionUsable(session, time.Now()) {
		return
	}
	connector.mu.Lock()
	defer connector.mu.Unlock()
	if connector.resourceSessions == nil {
		connector.resourceSessions = make(map[resourceSessionCacheKey]flowauthorization.AuthorizeResponse)
	}
	connector.resourceSessions[key] = session
}

func (connector *resourceStreamConnector) forgetResourceSession(key resourceSessionCacheKey) {
	if connector == nil || !key.cacheable() {
		return
	}
	connector.mu.Lock()
	defer connector.mu.Unlock()
	delete(connector.resourceSessions, key)
}

func (connector *resourceStreamConnector) withResourceSessionRenewal(stream net.Conn, key resourceSessionCacheKey, authorizer flowAuthorizer, request flowauthorization.AuthorizeRequest, authorization flowauthorization.AuthorizeResponse) net.Conn {
	if stream == nil || connector == nil || !key.cacheable() || !resourceSessionUsable(authorization, time.Now()) {
		return stream
	}
	renewCtx, cancel := context.WithCancel(context.Background())
	wrapped := &resourceSessionRenewConn{Conn: stream, cancel: cancel}
	go connector.renewResourceSessionUntilClosed(renewCtx, key, authorizer, request, authorization)
	return wrapped
}

func (connector *resourceStreamConnector) renewResourceSessionUntilClosed(ctx context.Context, key resourceSessionCacheKey, authorizer flowAuthorizer, request flowauthorization.AuthorizeRequest, authorization flowauthorization.AuthorizeResponse) {
	current := authorization
	for {
		wait := time.Until(current.ExpiresAt.Add(-resourceSessionRenewBefore))
		if wait < resourceSessionMinRenewWait {
			wait = resourceSessionMinRenewWait
		}
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return
		}
		renewCtx, cancel := context.WithTimeout(ctx, resourceSessionRenewTimeout)
		renewed, _, err := connector.authorizeResourceSession(renewCtx, key, authorizer, request, true)
		cancel()
		if err != nil {
			connector.warnResourceSession("resource session renew failed", key, current.SessionID, err)
			return
		}
		if err := validateAllowedResourceAuthorization(key.ResourceID, renewed); err != nil {
			connector.forgetResourceSession(key)
			connector.warnResourceSession("resource session renew rejected", key, current.SessionID, err)
			return
		}
		current = renewed
	}
}

func (connector *resourceStreamConnector) warnResourceSession(message string, key resourceSessionCacheKey, sessionID string, err error) {
	if connector == nil || connector.logger == nil {
		return
	}
	connector.logger.Warn(message, "resource_id", key.ResourceID, "session_id", sessionID, "error", err)
}

func validateAllowedResourceAuthorization(resourceID string, authorization flowauthorization.AuthorizeResponse) error {
	if !strings.EqualFold(strings.TrimSpace(authorization.Decision), flowauthorization.DecisionAllow) {
		decision := strings.TrimSpace(authorization.Decision)
		if decision == "" {
			decision = "deny"
		}
		reason := strings.TrimSpace(authorization.Reason)
		if reason == "" {
			reason = "policy decision did not allow the flow"
		}
		return fmt.Errorf("resource access %s: %s", decision, reason)
	}
	if strings.TrimSpace(authorization.SessionID) == "" || strings.TrimSpace(authorization.SessionToken) == "" {
		return fmt.Errorf("PDP allowed resource %s without Gateway session material", resourceID)
	}
	return nil
}

func isStepUpRequired(authorization flowauthorization.AuthorizeResponse) bool {
	decision := strings.ToLower(strings.TrimSpace(authorization.Decision))
	return decision == flowauthorization.DecisionStepUpRequired
}

func resourceSessionUsable(session flowauthorization.AuthorizeResponse, validAfter time.Time) bool {
	return strings.TrimSpace(session.SessionID) != "" &&
		strings.TrimSpace(session.SessionToken) != "" &&
		session.ExpiresAt.After(validAfter)
}

func (key resourceSessionCacheKey) cacheable() bool {
	return strings.TrimSpace(key.AgentSessionID) != "" &&
		strings.TrimSpace(key.ResourceID) != "" &&
		strings.TrimSpace(key.Protocol) != "" &&
		key.Port > 0
}

func isRetryableGatewaySessionError(err error) bool {
	var gatewayErr *gatewaytunnel.GatewayError
	if !errors.As(err, &gatewayErr) {
		return false
	}
	switch strings.TrimSpace(gatewayErr.Code) {
	case gatewaytunnel.CodeSessionInvalid, gatewaytunnel.CodeSessionExpired, gatewaytunnel.CodeSessionStoreUnavailable:
		return true
	default:
		return false
	}
}

type resourceSessionRenewConn struct {
	net.Conn
	cancel func()
	once   sync.Once
}

func (conn *resourceSessionRenewConn) Close() error {
	if conn == nil || conn.Conn == nil {
		return nil
	}
	conn.once.Do(func() {
		if conn.cancel != nil {
			conn.cancel()
		}
	})
	return conn.Conn.Close()
}

func (connector *resourceStreamConnector) recordAuthenticationRequired(request trafficinterception.StreamRequest) {
	if connector == nil || connector.onAuthenticationRequired == nil {
		return
	}
	connector.onAuthenticationRequired(request)
}

func (connector *resourceStreamConnector) recordStepUpRequired(request trafficinterception.StreamRequest, authorization flowauthorization.AuthorizeResponse) {
	if connector == nil || connector.onStepUpRequired == nil {
		return
	}
	connector.onStepUpRequired(request, authorization)
}

func (connector *resourceStreamConnector) recordResourceAllowed(request trafficinterception.StreamRequest, authorization flowauthorization.AuthorizeResponse) {
	if connector == nil || connector.onResourceAllowed == nil {
		return
	}
	connector.onResourceAllowed(request, authorization)
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
	case "":
		return "tcp"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func flowAuthorizationProcess(identity *trafficinterception.ProcessIdentity) *flowauthorization.ProcessIdentity {
	if identity == nil {
		return nil
	}
	return &flowauthorization.ProcessIdentity{
		PID:    identity.PID,
		Name:   strings.TrimSpace(identity.Name),
		Path:   strings.TrimSpace(identity.Path),
		SHA256: strings.TrimSpace(identity.SHA256),
		Signer: strings.TrimSpace(identity.Signer),
	}
}

func gatewayTunnelProcess(identity *trafficinterception.ProcessIdentity) *gatewaytunnel.ProcessIdentity {
	if identity == nil {
		return nil
	}
	return &gatewaytunnel.ProcessIdentity{
		PID:    identity.PID,
		Name:   strings.TrimSpace(identity.Name),
		Path:   strings.TrimSpace(identity.Path),
		SHA256: strings.TrimSpace(identity.SHA256),
		Signer: strings.TrimSpace(identity.Signer),
	}
}

func resourceSessionProcessKey(identity *trafficinterception.ProcessIdentity) string {
	if identity == nil {
		return ""
	}
	if value := strings.TrimSpace(identity.SHA256); value != "" {
		return "sha256:" + strings.ToLower(value)
	}
	if value := strings.TrimSpace(identity.Path); value != "" {
		return "path:" + strings.ToLower(value)
	}
	if value := strings.TrimSpace(identity.Name); value != "" {
		return "name:" + strings.ToLower(value)
	}
	if identity.PID > 0 {
		return fmt.Sprintf("pid:%d", identity.PID)
	}
	return ""
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
