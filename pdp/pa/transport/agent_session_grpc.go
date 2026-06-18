package transport

import (
	"context"
	"fmt"
	"strings"
	"time"

	"pdp/pa/auth"
	"pdp/pa/catalog"
	"pdp/util"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	agentSessionGRPCServiceName       = "trustagent.session.AgentSessionService"
	agentSessionGRPCStartSessionPath  = "/trustagent.session.AgentSessionService/StartSession"
	agentSessionGRPCSessionStatusPath = "/trustagent.session.AgentSessionService/SessionStatus"
	agentSessionGRPCClaimSessionPath  = "/trustagent.session.AgentSessionService/ClaimSession"
	agentSessionGRPCGetCatalogPath    = "/trustagent.session.AgentSessionService/GetCatalog"
	agentSessionGRPCRenewSessionPath  = "/trustagent.session.AgentSessionService/RenewSession"
	agentSessionGRPCRevokeSessionPath = "/trustagent.session.AgentSessionService/RevokeSession"
)

type agentSessionGRPCServer interface {
	StartSession(context.Context, *structpb.Struct) (*structpb.Struct, error)
	SessionStatus(context.Context, *structpb.Struct) (*structpb.Struct, error)
	ClaimSession(context.Context, *structpb.Struct) (*structpb.Struct, error)
	GetCatalog(context.Context, *structpb.Struct) (*structpb.Struct, error)
	RenewSession(context.Context, *structpb.Struct) (*structpb.Struct, error)
	RevokeSession(context.Context, *structpb.Struct) (*structpb.Struct, error)
}

type agentSessionGRPCService struct {
	server *Server
}

func (service *agentSessionGRPCService) StartSession(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	enrollment, peerThumbprint, err := service.authenticatedAgentDevice(ctx)
	if err != nil {
		return nil, err
	}
	deviceID := strings.TrimSpace(enrollment.DeviceID)
	if requested := strings.TrimSpace(structFieldString(request, "device_id")); requested != "" && requested != deviceID {
		return nil, status.Error(codes.PermissionDenied, "device_id does not match mTLS device identity")
	}
	if !structFieldBool(request, "session_renewal_required") {
		return nil, status.Error(codes.FailedPrecondition, "session renewal is required")
	}
	organizationID := strings.TrimSpace(enrollment.OrganizationID)
	if organizationID == "" {
		return nil, status.Error(codes.FailedPrecondition, "enrolled device has no organization context for user authentication")
	}
	localUser := structFieldStruct(request, "local_user")
	localUserSIDHash := strings.TrimSpace(structFieldString(localUser, "sid_hash"))
	windowsLogonSessionID := strings.TrimSpace(structFieldString(localUser, "windows_logon_session_id"))
	windowsSessionID := strings.TrimSpace(structFieldString(localUser, "windows_session_id"))
	if localUserSIDHash == "" || windowsLogonSessionID == "" || windowsSessionID == "" {
		return nil, status.Error(codes.InvalidArgument, "local_user sid_hash, windows_logon_session_id and windows_session_id are required")
	}
	publicOrigin, err := service.server.publicOrigin()
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	sessionID, err := util.GenerateID("srq")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate session request id: %v", err)
	}
	claimSecret, err := randomSessionSecret(32)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate claim secret: %v", err)
	}
	now := time.Now().UTC()
	expiresAt := now.Add(service.server.appConfig().Runtime.BrowserAuthSessionTTL)
	if expiresAt.Equal(now) {
		expiresAt = now.Add(5 * time.Minute)
	}
	session := &agentSessionTransaction{
		ID:                     sessionID,
		OrganizationID:         organizationID,
		DeviceID:               deviceID,
		DeviceCertThumbprint:   peerThumbprint,
		LocalUserSIDHash:       localUserSIDHash,
		WindowsLogonSessionID:  windowsLogonSessionID,
		WindowsSessionID:       windowsSessionID,
		DeviceDataRevision:     strings.TrimSpace(structFieldString(request, "device_data_revision")),
		SessionRenewalRequired: true,
		ClaimSecretHash:        hashSessionSecret(claimSecret),
		AuthURL:                publicOrigin + "/browser/session/" + sessionID,
		Status:                 agentSessionStatusWaitingForUserLogin,
		PolicyEpoch:            1,
		CreatedAt:              now,
		ExpiresAt:              expiresAt,
	}
	service.server.agentSessions.save(session)
	if service.server.pa.Audit != nil {
		service.server.pa.Audit.LogEvent("agent_user_authentication_request", "", "", grpcPeerIP(ctx), deviceID, "",
			"User authentication requested for TrustAgent session", true)
	}
	return structpb.NewStruct(map[string]interface{}{
		"session_request_id":    session.ID,
		"auth_url":              session.AuthURL,
		"claim_secret":          claimSecret,
		"status":                session.Status,
		"expires_at":            session.ExpiresAt.Format(time.RFC3339Nano),
		"poll_interval_seconds": float64(3),
	})
}

func (service *agentSessionGRPCService) SessionStatus(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	session, err := service.validatedSessionRequest(ctx, request)
	if err != nil {
		return nil, err
	}
	payload := map[string]interface{}{"status": session.Status}
	if session.Reason != "" {
		payload["reason"] = session.Reason
	}
	return structpb.NewStruct(payload)
}

func (service *agentSessionGRPCService) ClaimSession(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	session, err := service.validatedSessionRequest(ctx, request)
	if err != nil {
		return nil, err
	}
	if time.Now().UTC().After(session.ExpiresAt) {
		return nil, status.Error(codes.FailedPrecondition, "session request expired")
	}
	if session.Status != agentSessionStatusReadyToClaim {
		return nil, status.Errorf(codes.FailedPrecondition, "session is not ready to claim: %s", session.Status)
	}
	if session.SingleUseConsumed {
		return nil, status.Error(codes.FailedPrecondition, "session request was already claimed")
	}
	if !session.SessionRenewalRequired || !structFieldBool(request, "session_renewal_required") {
		return nil, status.Error(codes.FailedPrecondition, "session renewal is required")
	}
	localUser := structFieldStruct(request, "local_user")
	localUserSIDHash := strings.TrimSpace(structFieldString(localUser, "sid_hash"))
	windowsLogonSessionID := strings.TrimSpace(structFieldString(localUser, "windows_logon_session_id"))
	windowsSessionID := strings.TrimSpace(structFieldString(localUser, "windows_session_id"))
	if localUserSIDHash == "" || windowsLogonSessionID == "" || windowsSessionID == "" {
		return nil, status.Error(codes.InvalidArgument, "local_user sid_hash, windows_logon_session_id and windows_session_id are required")
	}
	if localUserSIDHash != session.LocalUserSIDHash {
		return nil, status.Error(codes.PermissionDenied, "local user SID hash does not match session request")
	}
	if windowsLogonSessionID != session.WindowsLogonSessionID {
		return nil, status.Error(codes.PermissionDenied, "Windows logon session does not match session request")
	}
	if windowsSessionID != session.WindowsSessionID {
		return nil, status.Error(codes.PermissionDenied, "Windows session does not match session request")
	}
	agentSessionID, err := util.GenerateID("sess")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate agent session id: %v", err)
	}
	now := time.Now().UTC()
	idleExpiresAt, absoluteExpiresAt, serverExpiresAt := service.agentSessionExpiryBounds(now)
	tokenSession := *session
	tokenSession.AgentSessionID = agentSessionID
	tokenSession.LastActivityAt = now
	tokenSession.IdleExpiresAt = idleExpiresAt
	tokenSession.AbsoluteExpiresAt = absoluteExpiresAt
	tokenSession.ExpiresAt = serverExpiresAt
	token, tokenExpiresAt, err := service.issueAgentSessionToken(&tokenSession, agentSessionID, now)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "issue agent session token: %v", err)
	}
	claimed, err := service.server.agentSessions.update(session.ID, func(live *agentSessionTransaction) error {
		if live.SingleUseConsumed || live.Status != agentSessionStatusReadyToClaim {
			return fmt.Errorf("session cannot be claimed")
		}
		live.AgentSessionID = agentSessionID
		live.LastActivityAt = now
		live.IdleExpiresAt = idleExpiresAt
		live.AbsoluteExpiresAt = absoluteExpiresAt
		live.ExpiresAt = serverExpiresAt
		live.SingleUseConsumed = true
		live.Status = agentSessionStatusClaimed
		return nil
	})
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return service.agentSessionTokenResponse(claimed, token, tokenExpiresAt)
}

func (service *agentSessionGRPCService) GetCatalog(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	enrollment, peerThumbprint, err := service.authenticatedAgentDevice(ctx)
	if err != nil {
		return nil, err
	}
	token, tokenErr := catalogBearerTokenFromGRPC(ctx, request)
	if tokenErr != nil {
		return nil, status.Error(codes.Unauthenticated, tokenErr.Error())
	}
	claims, statusCode, err := service.server.validateDeviceCatalogToken(token, enrollment.DeviceID, peerThumbprint)
	if err != nil {
		return nil, status.Error(grpcCodeForHTTPStatus(statusCode), err.Error())
	}
	return catalogSnapshotStruct(service.server.deviceCatalogSnapshot(claims))
}

func (service *agentSessionGRPCService) RenewSession(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	enrollment, peerThumbprint, err := service.authenticatedAgentDevice(ctx)
	if err != nil {
		return nil, err
	}
	token, tokenErr := catalogBearerTokenFromGRPC(ctx, request)
	if tokenErr != nil {
		return nil, status.Error(codes.Unauthenticated, tokenErr.Error())
	}
	claims, err := service.server.pa.ValidateDeviceUserTokenBoundForScope(token, enrollment.DeviceID, peerThumbprint, "session:renew")
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	sessionID := strings.TrimSpace(structFieldString(request, "session_id"))
	if sessionID != "" && strings.TrimSpace(claims.SessionID) != "" && sessionID != strings.TrimSpace(claims.SessionID) {
		return nil, status.Error(codes.PermissionDenied, "session_id does not match agent session token")
	}
	if strings.TrimSpace(claims.SessionID) == "" {
		return nil, status.Error(codes.Unauthenticated, "agent session token has no session_id")
	}
	session, ok := service.server.agentSessions.getByAgentSessionID(claims.SessionID)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "agent session is no longer active")
	}
	now := time.Now().UTC()
	if err := validateClaimedAgentSessionForToken(session, claims, peerThumbprint, now); err != nil {
		return nil, err
	}
	renewed, err := service.server.agentSessions.updateByAgentSessionID(claims.SessionID, func(live *agentSessionTransaction) error {
		if err := validateClaimedAgentSessionForToken(live, claims, peerThumbprint, now); err != nil {
			return err
		}
		if claims.ID != "" && claims.ExpiresAt != nil {
			service.server.pa.Store.RevokeToken(claims.ID, claims.ExpiresAt.Time)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	renewedToken, renewedExpiresAt, err := service.issueAgentSessionToken(renewed, renewed.AgentSessionID, now)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "renew agent session token: %v", err)
	}
	return service.agentSessionTokenResponse(renewed, renewedToken, renewedExpiresAt)
}

func (service *agentSessionGRPCService) RevokeSession(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	enrollment, peerThumbprint, err := service.authenticatedAgentDevice(ctx)
	if err != nil {
		return nil, err
	}
	token, tokenErr := catalogBearerTokenFromGRPC(ctx, request)
	if tokenErr != nil {
		return nil, status.Error(codes.Unauthenticated, tokenErr.Error())
	}
	claims, err := service.server.pa.ValidateDeviceUserTokenBoundForScope(token, enrollment.DeviceID, peerThumbprint, "session:revoke")
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	sessionID := strings.TrimSpace(structFieldString(request, "session_id"))
	if sessionID != "" && strings.TrimSpace(claims.SessionID) != "" && sessionID != strings.TrimSpace(claims.SessionID) {
		return nil, status.Error(codes.PermissionDenied, "session_id does not match agent session token")
	}
	if claims.ID != "" && claims.ExpiresAt != nil {
		service.server.pa.Store.RevokeToken(claims.ID, claims.ExpiresAt.Time)
	}
	if strings.TrimSpace(claims.SessionID) != "" {
		service.server.agentSessions.deleteByAgentSessionID(claims.SessionID)
	}
	revokedResourceSessions := 0
	if service.server.pa.Sessions != nil {
		revokedResourceSessions = service.server.pa.Sessions.RevokeSessionsForDeviceUser(claims.UserID, claims.DeviceID, claims.OrganizationID, "agent_logout")
	}
	return structpb.NewStruct(map[string]interface{}{
		"revoked":                   true,
		"revoked_resource_sessions": float64(revokedResourceSessions),
	})
}

func (service *agentSessionGRPCService) issueAgentSessionToken(session *agentSessionTransaction, agentSessionID string, now time.Time) (string, time.Time, error) {
	if session == nil {
		return "", time.Time{}, fmt.Errorf("agent session is required")
	}
	ttl := service.server.appConfig().Runtime.AgentSessionAccessTokenTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	serverExpiresAt := minNonZeroTime(session.IdleExpiresAt, session.AbsoluteExpiresAt)
	if serverExpiresAt.IsZero() {
		return "", time.Time{}, fmt.Errorf("agent session has no server-side idle and absolute timeout")
	}
	if !serverExpiresAt.IsZero() {
		remaining := serverExpiresAt.UTC().Sub(now)
		if remaining <= 0 {
			return "", time.Time{}, fmt.Errorf("agent session expired")
		}
		if ttl > remaining {
			ttl = remaining
		}
	}
	role := strings.TrimSpace(session.AuthenticatedUserRole)
	if role == "" {
		role = "user"
	}
	return service.server.pa.Auth.JWT.GenerateAgentSessionToken(auth.AgentSessionTokenRequest{
		SessionID:                   agentSessionID,
		UserID:                      session.AuthenticatedUserID,
		Username:                    firstNonEmptyAgentSession(session.AuthenticatedUserEmail, session.AuthenticatedUsername),
		Role:                        role,
		OrganizationID:              session.OrganizationID,
		DeviceID:                    session.DeviceID,
		LocalUserSIDHash:            session.LocalUserSIDHash,
		WindowsLogonSessionID:       session.WindowsLogonSessionID,
		WindowsSessionID:            session.WindowsSessionID,
		CertificateThumbprintSHA256: session.DeviceCertThumbprint,
		DeviceDataRevision:          session.DeviceDataRevision,
		PolicyEpoch:                 session.PolicyEpoch,
		ACR:                         "urn:trustcloud:loa:1",
		AMR:                         []string{"idp"},
		TTL:                         ttl,
	})
}

func (service *agentSessionGRPCService) agentSessionExpiryBounds(now time.Time) (time.Time, time.Time, time.Time) {
	absoluteTTL := service.server.appConfig().Runtime.AgentSessionAbsoluteTTL
	if absoluteTTL <= 0 {
		absoluteTTL = 8 * time.Hour
	}
	absoluteExpiresAt := now.Add(absoluteTTL)
	idleExpiresAt := service.agentSessionNextIdleExpiry(now, absoluteExpiresAt)
	return idleExpiresAt, absoluteExpiresAt, minNonZeroTime(idleExpiresAt, absoluteExpiresAt)
}

func (service *agentSessionGRPCService) agentSessionNextIdleExpiry(now, absoluteExpiresAt time.Time) time.Time {
	idleTTL := service.server.appConfig().Runtime.AgentSessionIdleTTL
	if idleTTL <= 0 {
		idleTTL = 30 * time.Minute
	}
	idleExpiresAt := now.Add(idleTTL).UTC()
	if !absoluteExpiresAt.IsZero() && absoluteExpiresAt.UTC().Before(idleExpiresAt) {
		return absoluteExpiresAt.UTC()
	}
	return idleExpiresAt
}

func (service *agentSessionGRPCService) agentSessionTokenResponse(session *agentSessionTransaction, token string, tokenExpiresAt time.Time) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]interface{}{
		"status":              session.Status,
		"agent_session_id":    session.AgentSessionID,
		"agent_session_token": token,
		"expires_at":          tokenExpiresAt.UTC().Format(time.RFC3339Nano),
		"idle_expires_at":     session.IdleExpiresAt.UTC().Format(time.RFC3339Nano),
		"absolute_expires_at": session.AbsoluteExpiresAt.UTC().Format(time.RFC3339Nano),
		"policy_epoch":        float64(session.PolicyEpoch),
		"user": map[string]interface{}{
			"idp_issuer":   session.AuthenticatedUserIssuer,
			"subject":      session.AuthenticatedUserSubject,
			"email":        firstNonEmptyAgentSession(session.AuthenticatedUserEmail, session.AuthenticatedUsername),
			"display_name": firstNonEmptyAgentSession(session.AuthenticatedUserEmail, session.AuthenticatedUsername),
		},
	})
}

func validateClaimedAgentSessionForToken(session *agentSessionTransaction, claims *auth.CustomClaims, peerThumbprint string, now time.Time) error {
	if session == nil {
		return status.Error(codes.Unauthenticated, "agent session is no longer active")
	}
	if session.Status != agentSessionStatusClaimed || strings.TrimSpace(session.AgentSessionID) == "" {
		return status.Error(codes.Unauthenticated, "agent session is not active")
	}
	if strings.TrimSpace(session.AgentSessionID) != strings.TrimSpace(claims.SessionID) {
		return status.Error(codes.PermissionDenied, "session_id does not match agent session state")
	}
	if strings.TrimSpace(session.DeviceID) != strings.TrimSpace(claims.DeviceID) {
		return status.Error(codes.PermissionDenied, "device_id does not match agent session state")
	}
	if strings.TrimSpace(session.OrganizationID) != strings.TrimSpace(claims.OrganizationID) {
		return status.Error(codes.PermissionDenied, "organization_id does not match agent session state")
	}
	if strings.TrimSpace(session.DeviceCertThumbprint) != strings.TrimSpace(peerThumbprint) {
		return status.Error(codes.PermissionDenied, "certificate thumbprint does not match agent session state")
	}
	if strings.TrimSpace(session.LocalUserSIDHash) != strings.TrimSpace(claims.LocalUserSIDHash) {
		return status.Error(codes.PermissionDenied, "local user does not match agent session state")
	}
	if strings.TrimSpace(session.WindowsLogonSessionID) != strings.TrimSpace(claims.WindowsLogonSessionID) {
		return status.Error(codes.PermissionDenied, "Windows logon session does not match agent session state")
	}
	if strings.TrimSpace(session.WindowsSessionID) != strings.TrimSpace(claims.WindowsSessionID) {
		return status.Error(codes.PermissionDenied, "Windows session does not match agent session state")
	}
	if session.IdleExpiresAt.IsZero() || !now.Before(session.IdleExpiresAt.UTC()) {
		return status.Error(codes.Unauthenticated, "agent session idle timeout expired")
	}
	if session.AbsoluteExpiresAt.IsZero() || !now.Before(session.AbsoluteExpiresAt.UTC()) {
		return status.Error(codes.Unauthenticated, "agent session absolute timeout expired")
	}
	return nil
}

func minNonZeroTime(values ...time.Time) time.Time {
	var result time.Time
	for _, value := range values {
		if value.IsZero() {
			continue
		}
		value = value.UTC()
		if result.IsZero() || value.Before(result) {
			result = value
		}
	}
	return result
}

func (service *agentSessionGRPCService) authenticatedAgentDevice(ctx context.Context) (deviceEnrollment, string, error) {
	if service == nil || service.server == nil || service.server.pa == nil || service.server.pa.Auth == nil {
		return deviceEnrollment{}, "", status.Error(codes.Internal, "agent session service is not initialized")
	}
	enrollment, ok := deviceEnrollmentFromContextValue(ctx)
	if !ok || strings.TrimSpace(enrollment.DeviceID) == "" {
		return deviceEnrollment{}, "", status.Error(codes.PermissionDenied, "missing client certificate identity")
	}
	peerCert, ok := clientCertificateFromGRPCContext(ctx)
	if !ok {
		return deviceEnrollment{}, "", status.Error(codes.Unauthenticated, "client certificate required")
	}
	return deviceEnrollment{
		DeviceID:       enrollment.DeviceID,
		OrganizationID: enrollment.OrganizationID,
	}, clientCertificateFingerprint(peerCert), nil
}

type deviceEnrollment struct {
	DeviceID       string
	OrganizationID string
}

func (service *agentSessionGRPCService) validatedSessionRequest(ctx context.Context, request *structpb.Struct) (*agentSessionTransaction, error) {
	enrollment, peerThumbprint, err := service.authenticatedAgentDevice(ctx)
	if err != nil {
		return nil, err
	}
	sessionID := strings.TrimSpace(structFieldString(request, "session_request_id"))
	session, ok := service.server.agentSessions.get(sessionID)
	if !ok {
		return nil, status.Error(codes.NotFound, "session request not found")
	}
	if session.DeviceID != enrollment.DeviceID {
		return nil, status.Error(codes.PermissionDenied, "session device does not match mTLS device identity")
	}
	if session.DeviceCertThumbprint != peerThumbprint {
		return nil, status.Error(codes.PermissionDenied, "session certificate thumbprint does not match mTLS device certificate")
	}
	claimSecret := strings.TrimSpace(structFieldString(request, "claim_secret"))
	if claimSecret == "" {
		return nil, status.Error(codes.InvalidArgument, "claim_secret is required")
	}
	if hashSessionSecret(claimSecret) != session.ClaimSecretHash {
		return nil, status.Error(codes.PermissionDenied, "claim_secret does not match session request")
	}
	return session, nil
}

func catalogSnapshotStruct(snapshot catalog.Snapshot) (*structpb.Struct, error) {
	resourceValues := make([]interface{}, 0, len(snapshot.Resources))
	for _, resource := range snapshot.Resources {
		resourceValues = append(resourceValues, map[string]interface{}{
			"fqdn":         resource.FQDN,
			"resource_id":  resource.ResourceID,
			"display_name": resource.ResourceID,
			"protocol":     resource.Protocol,
			"port":         float64(resource.Port),
			"access_mode":  resource.Protocol,
		})
	}
	deviceDataChecks := make([]interface{}, 0, len(snapshot.DeviceDataPolicy.RequiredChecks))
	for _, check := range snapshot.DeviceDataPolicy.RequiredChecks {
		deviceDataChecks = append(deviceDataChecks, check)
	}
	return structpb.NewStruct(map[string]interface{}{
		"version":      snapshot.Version,
		"resources":    resourceValues,
		"ttl_seconds":  float64(snapshot.TTLSeconds),
		"policy_epoch": snapshot.PolicyEpoch,
		"device_data_policy": map[string]interface{}{
			"required_checks":       deviceDataChecks,
			"required_check_status": snapshot.DeviceDataPolicy.RequiredCheckStatus,
		},
	})
}

func agentSessionStartSessionHandler(srv interface{}, ctx context.Context, decoder func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	request := &structpb.Struct{}
	if err := decoder(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(agentSessionGRPCServer).StartSession(ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: agentSessionGRPCStartSessionPath}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(agentSessionGRPCServer).StartSession(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, request, info, handler)
}

func agentSessionStatusHandler(srv interface{}, ctx context.Context, decoder func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	request := &structpb.Struct{}
	if err := decoder(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(agentSessionGRPCServer).SessionStatus(ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: agentSessionGRPCSessionStatusPath}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(agentSessionGRPCServer).SessionStatus(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, request, info, handler)
}

func agentSessionClaimHandler(srv interface{}, ctx context.Context, decoder func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	request := &structpb.Struct{}
	if err := decoder(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(agentSessionGRPCServer).ClaimSession(ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: agentSessionGRPCClaimSessionPath}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(agentSessionGRPCServer).ClaimSession(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, request, info, handler)
}

func agentSessionCatalogHandler(srv interface{}, ctx context.Context, decoder func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	request := &structpb.Struct{}
	if err := decoder(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(agentSessionGRPCServer).GetCatalog(ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: agentSessionGRPCGetCatalogPath}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(agentSessionGRPCServer).GetCatalog(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, request, info, handler)
}

func agentSessionRenewHandler(srv interface{}, ctx context.Context, decoder func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	request := &structpb.Struct{}
	if err := decoder(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(agentSessionGRPCServer).RenewSession(ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: agentSessionGRPCRenewSessionPath}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(agentSessionGRPCServer).RenewSession(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, request, info, handler)
}

func agentSessionRevokeHandler(srv interface{}, ctx context.Context, decoder func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	request := &structpb.Struct{}
	if err := decoder(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(agentSessionGRPCServer).RevokeSession(ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: agentSessionGRPCRevokeSessionPath}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(agentSessionGRPCServer).RevokeSession(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, request, info, handler)
}

var agentSessionGRPCServiceDesc = grpc.ServiceDesc{
	ServiceName: agentSessionGRPCServiceName,
	HandlerType: (*agentSessionGRPCServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "StartSession", Handler: agentSessionStartSessionHandler},
		{MethodName: "SessionStatus", Handler: agentSessionStatusHandler},
		{MethodName: "ClaimSession", Handler: agentSessionClaimHandler},
		{MethodName: "GetCatalog", Handler: agentSessionCatalogHandler},
		{MethodName: "RenewSession", Handler: agentSessionRenewHandler},
		{MethodName: "RevokeSession", Handler: agentSessionRevokeHandler},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "trustagent_session.proto",
}
