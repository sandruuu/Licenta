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
	resourceSessionRenewals  map[string]*resourceSessionRenewal
	onAuthenticationRequired func(trafficinterception.StreamRequest)
	onStepUpRequired         func(trafficinterception.StreamRequest, flowauthorization.AuthorizeResponse)
	onResourceAllowed        func(trafficinterception.StreamRequest, flowauthorization.AuthorizeResponse)
	onResourceDenied         func(trafficinterception.StreamRequest, flowauthorization.AuthorizeResponse, error)
}

type resourceSessionCacheKey struct {
	AgentSessionID string
	ResourceID     string
	Protocol       string
	Port           int
	ProcessKey     string
}

type resourceSessionRenewal struct {
	cancel context.CancelFunc
	refs   int
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
		connector.recordResourceDenied(request, authorization, err)
		return nil, err
	}
	connector.recordResourceAllowed(request, authorization)
	if strings.TrimSpace(authorization.GatewayEndpoint) == "" {
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
		GatewayEndpoint:   strings.TrimSpace(authorization.GatewayEndpoint),
		GatewayServerName: authorization.GatewayServerName,
		Process:           gatewayProcess,
	}
	stream, err := tunnel.OpenResourceStream(ctx, streamRequest)
	if err != nil && fromCache && isRetryableGatewaySessionError(err) {
		connector.forgetResourceSession(cacheKey)
		authRequest, err = connector.authorizeRequestWithCurrentAgentToken(authRequest, cacheKey.AgentSessionID)
		if err != nil {
			return nil, fmt.Errorf("refresh agent session token for resource %s: %w", request.ResourceID, err)
		}
		authorization, _, err = connector.authorizeResourceSession(ctx, cacheKey, authorizer, authRequest, true)
		if err != nil {
			return nil, fmt.Errorf("reauthorize resource %s: %w", request.ResourceID, err)
		}
		if isStepUpRequired(authorization) {
			connector.recordStepUpRequired(request, authorization)
			return nil, fmt.Errorf("%w: %s", ErrStepUpRequired, firstNonEmpty(authorization.Reason, "additional verification required"))
		}
		if err := validateAllowedResourceAuthorization(request.ResourceID, authorization); err != nil {
			connector.recordResourceDenied(request, authorization, err)
			return nil, err
		}
		connector.recordResourceAllowed(request, authorization)
		streamRequest.SessionID = authorization.SessionID
		streamRequest.SessionToken = authorization.SessionToken
		streamRequest.ResourceID = firstNonEmpty(authorization.ResourceID, request.ResourceID)
		streamRequest.GatewayID = authorization.GatewayID
		streamRequest.GatewayEndpoint = strings.TrimSpace(authorization.GatewayEndpoint)
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
	var cancel context.CancelFunc
	var sessionID string
	connector.mu.Lock()
	if connector.resourceSessions != nil {
		sessionID = strings.TrimSpace(connector.resourceSessions[key].SessionID)
		delete(connector.resourceSessions, key)
	}
	if connector.resourceSessionRenewals != nil && sessionID != "" {
		if renewal := connector.resourceSessionRenewals[sessionID]; renewal != nil {
			cancel = renewal.cancel
			delete(connector.resourceSessionRenewals, sessionID)
		}
	}
	connector.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (connector *resourceStreamConnector) forgetResourceSessionID(sessionID string) {
	if connector == nil {
		return
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return
	}
	var cancel context.CancelFunc
	connector.mu.Lock()
	for key, session := range connector.resourceSessions {
		if strings.TrimSpace(session.SessionID) == sessionID {
			delete(connector.resourceSessions, key)
		}
	}
	if connector.resourceSessionRenewals != nil {
		if renewal := connector.resourceSessionRenewals[sessionID]; renewal != nil {
			cancel = renewal.cancel
			delete(connector.resourceSessionRenewals, sessionID)
		}
	}
	connector.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (connector *resourceStreamConnector) refreshResourceSessionID(sessionID string, refreshed flowauthorization.AuthorizeResponse) {
	if connector == nil || !resourceSessionUsable(refreshed, time.Now()) {
		return
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" || strings.TrimSpace(refreshed.SessionID) != sessionID {
		return
	}
	connector.mu.Lock()
	for key, session := range connector.resourceSessions {
		if strings.TrimSpace(session.SessionID) == sessionID {
			connector.resourceSessions[key] = refreshed
		}
	}
	connector.mu.Unlock()
}

func (connector *resourceStreamConnector) withResourceSessionRenewal(stream net.Conn, key resourceSessionCacheKey, authorizer flowAuthorizer, request flowauthorization.AuthorizeRequest, authorization flowauthorization.AuthorizeResponse) net.Conn {
	if stream == nil || connector == nil || !key.cacheable() || !resourceSessionUsable(authorization, time.Now()) {
		return stream
	}
	release := connector.acquireResourceSessionRenewal(key, authorizer, request, authorization)
	if release == nil {
		return stream
	}
	wrapped := &resourceSessionRenewConn{Conn: stream, release: release}
	return wrapped
}

func (connector *resourceStreamConnector) acquireResourceSessionRenewal(key resourceSessionCacheKey, authorizer flowAuthorizer, request flowauthorization.AuthorizeRequest, authorization flowauthorization.AuthorizeResponse) func() {
	if connector == nil || !key.cacheable() || !resourceSessionUsable(authorization, time.Now()) {
		return nil
	}
	sessionID := strings.TrimSpace(authorization.SessionID)
	if sessionID == "" {
		return nil
	}
	renewCtx, cancel := context.WithCancel(context.Background())
	renewal := &resourceSessionRenewal{cancel: cancel, refs: 1}

	connector.mu.Lock()
	if connector.resourceSessionRenewals == nil {
		connector.resourceSessionRenewals = make(map[string]*resourceSessionRenewal)
	}
	if existing := connector.resourceSessionRenewals[sessionID]; existing != nil {
		existing.refs++
		connector.mu.Unlock()
		cancel()
		return func() { connector.releaseResourceSessionRenewal(sessionID, existing) }
	}
	connector.resourceSessionRenewals[sessionID] = renewal
	connector.mu.Unlock()

	go connector.renewResourceSessionUntilReleased(renewCtx, key, authorizer, request, authorization, renewal)
	return func() { connector.releaseResourceSessionRenewal(sessionID, renewal) }
}

func (connector *resourceStreamConnector) releaseResourceSessionRenewal(sessionID string, renewal *resourceSessionRenewal) {
	if connector == nil || renewal == nil {
		return
	}
	sessionID = strings.TrimSpace(sessionID)
	var cancel context.CancelFunc
	connector.mu.Lock()
	if connector.resourceSessionRenewals != nil && connector.resourceSessionRenewals[sessionID] == renewal {
		renewal.refs--
		if renewal.refs <= 0 {
			cancel = renewal.cancel
			delete(connector.resourceSessionRenewals, sessionID)
		}
	}
	connector.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (connector *resourceStreamConnector) finishResourceSessionRenewal(sessionID string, renewal *resourceSessionRenewal) {
	if connector == nil || renewal == nil {
		return
	}
	sessionID = strings.TrimSpace(sessionID)
	connector.mu.Lock()
	if connector.resourceSessionRenewals != nil && connector.resourceSessionRenewals[sessionID] == renewal {
		delete(connector.resourceSessionRenewals, sessionID)
	}
	connector.mu.Unlock()
}

func (connector *resourceStreamConnector) renewResourceSessionUntilReleased(ctx context.Context, key resourceSessionCacheKey, authorizer flowAuthorizer, request flowauthorization.AuthorizeRequest, authorization flowauthorization.AuthorizeResponse, renewal *resourceSessionRenewal) {
	sessionID := strings.TrimSpace(authorization.SessionID)
	defer connector.finishResourceSessionRenewal(sessionID, renewal)
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
		renewRequest, requestErr := connector.authorizeRequestWithCurrentAgentToken(request, key.AgentSessionID)
		if requestErr != nil {
			cancel()
			connector.warnResourceSession("resource session renew could not load current agent token", key, current.SessionID, requestErr)
			return
		}
		renewed, _, err := connector.authorizeResourceSession(renewCtx, key, authorizer, renewRequest, true)
		cancel()
		if err != nil {
			connector.warnResourceSession("resource session renew failed", key, current.SessionID, err)
			return
		}
		if err := validateAllowedResourceAuthorization(key.ResourceID, renewed); err != nil {
			connector.forgetResourceSessionID(current.SessionID)
			connector.warnResourceSession("resource session renew rejected", key, current.SessionID, err)
			return
		}
		if strings.TrimSpace(renewed.SessionID) != strings.TrimSpace(current.SessionID) {
			connector.warnResourceSession("resource session renew returned replacement session", key, current.SessionID, fmt.Errorf("new_session_id=%s", strings.TrimSpace(renewed.SessionID)))
			return
		}
		connector.refreshResourceSessionID(current.SessionID, renewed)
		current = renewed
	}
}

func (connector *resourceStreamConnector) authorizeRequestWithCurrentAgentToken(request flowauthorization.AuthorizeRequest, agentSessionID string) (flowauthorization.AuthorizeRequest, error) {
	if connector == nil || connector.userSessions == nil {
		return request, fmt.Errorf("user session provider is unavailable")
	}
	session, found, err := connector.userSessions.ActiveAuthenticatedSession()
	if err != nil {
		return request, err
	}
	if !found {
		return request, ErrAuthenticationRequired
	}
	if strings.TrimSpace(session.AgentSessionID) != strings.TrimSpace(agentSessionID) {
		return request, fmt.Errorf("active agent session changed")
	}
	request.AgentSessionToken = session.AgentSessionToken
	return request, nil
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
	release func()
	once    sync.Once
}

func (conn *resourceSessionRenewConn) Close() error {
	if conn == nil || conn.Conn == nil {
		return nil
	}
	conn.once.Do(func() {
		if conn.release != nil {
			conn.release()
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

func (connector *resourceStreamConnector) recordResourceDenied(request trafficinterception.StreamRequest, authorization flowauthorization.AuthorizeResponse, err error) {
	if connector == nil || connector.onResourceDenied == nil {
		return
	}
	connector.onResourceDenied(request, authorization, err)
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
