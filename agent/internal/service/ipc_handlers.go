package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"agent/internal/platform/process"
	"agent/internal/service/dnsresolver"
	agentnetwork "agent/internal/service/network"
	"agent/internal/service/tunnel"
	"agent/internal/shared/ipc"
)

func (service *Service) HandleIPC(ctx context.Context, request *ipc.Request) (*ipc.Response, error) {
	if request == nil {
		return nil, errors.New("ipc request is nil")
	}
	switch request.Operation {
	case ipc.OperationPing:
		var payload ipc.PingRequest
		if err := ipc.DecodeBody(request.Body, &payload); err != nil {
			return ipc.NewErrorResponse(request.ID, ipc.ErrorCodeInvalidRequest, err.Error()), nil
		}
		return ipc.NewResponse(request.ID, service.ping(payload))
	case ipc.OperationGetStatus:
		return ipc.NewResponse(request.ID, service.status())
	case ipc.OperationGetDashboard:
		var payload ipc.DashboardRequest
		if err := ipc.DecodeBody(request.Body, &payload); err != nil {
			return ipc.NewErrorResponse(request.ID, ipc.ErrorCodeInvalidRequest, err.Error()), nil
		}
		return ipc.NewResponse(request.ID, service.dashboard(ctx))
	case ipc.OperationGetCatalogResources:
		var payload ipc.CatalogResourcesRequest
		if err := ipc.DecodeBody(request.Body, &payload); err != nil {
			return ipc.NewErrorResponse(request.ID, ipc.ErrorCodeInvalidRequest, err.Error()), nil
		}
		return ipc.NewResponse(request.ID, service.catalogResourcesResponse())
	case ipc.OperationGetActiveSessions:
		var payload ipc.ActiveSessionsRequest
		if err := ipc.DecodeBody(request.Body, &payload); err != nil {
			return ipc.NewErrorResponse(request.ID, ipc.ErrorCodeInvalidRequest, err.Error()), nil
		}
		return ipc.NewResponse(request.ID, service.activeSessionsResponse())
	case ipc.OperationGetAccessEvents:
		var payload ipc.AccessEventsRequest
		if err := ipc.DecodeBody(request.Body, &payload); err != nil {
			return ipc.NewErrorResponse(request.ID, ipc.ErrorCodeInvalidRequest, err.Error()), nil
		}
		return ipc.NewResponse(request.ID, service.accessEventsResponse())
	case ipc.OperationGetDevicePosture:
		var payload ipc.DevicePostureRequest
		if err := ipc.DecodeBody(request.Body, &payload); err != nil {
			return ipc.NewErrorResponse(request.ID, ipc.ErrorCodeInvalidRequest, err.Error()), nil
		}
		report, code, err := service.devicePosture(ctx)
		if err != nil {
			return ipc.NewErrorResponse(request.ID, code, err.Error()), nil
		}
		return ipc.NewResponse(request.ID, report)
	case ipc.OperationStartEnrollment:
		var payload ipc.StartEnrollmentRequest
		if err := ipc.DecodeBody(request.Body, &payload); err != nil {
			return ipc.NewErrorResponse(request.ID, ipc.ErrorCodeInvalidRequest, err.Error()), nil
		}
		response, code, err := service.startEnrollment(ctx, payload)
		if err != nil {
			return ipc.NewErrorResponse(request.ID, code, err.Error()), nil
		}
		return ipc.NewResponse(request.ID, response)
	case ipc.OperationUpdateAccessToken:
		var payload ipc.UpdateAccessTokenRequest
		if err := ipc.DecodeBody(request.Body, &payload); err != nil {
			return ipc.NewErrorResponse(request.ID, ipc.ErrorCodeInvalidRequest, err.Error()), nil
		}
		response, code, err := service.updateAccessToken(ctx, payload)
		if err != nil {
			return ipc.NewErrorResponse(request.ID, code, err.Error()), nil
		}
		return ipc.NewResponse(request.ID, response)
	default:
		return ipc.NewErrorResponse(request.ID, ipc.ErrorCodeUnsupported, "unsupported IPC operation"), nil
	}
}

func (service *Service) ping(payload ipc.PingRequest) ipc.PingResponse {
	identity := process.Current()
	message := strings.TrimSpace(payload.Message)
	if message == "" {
		message = "ping"
	}
	return ipc.PingResponse{
		Message:           "pong from service",
		Echo:              message,
		Protocol:          ipc.ProtocolVersion,
		PipeName:          ipc.PipePath(),
		ServiceState:      string(service.State()),
		ServicePID:        identity.PID,
		ServiceUser:       identity.Username,
		ServiceUserSID:    identity.UserSID,
		AuthorizedUserSID: service.AuthorizedUserSID(),
		ReceivedAt:        time.Now().UTC(),
	}
}

func (service *Service) status() ipc.AgentStatus {
	service.refreshIdentitySnapshot(context.Background())
	identity := process.Current()
	service.mu.RLock()
	enrollment := service.enrollment
	session := service.session
	posture := service.posture
	catalogState := service.catalog
	serviceState := service.state
	authorizedUserSID := service.authorizedUserSID
	service.mu.RUnlock()
	syntheticStatus := dnsresolver.Status{State: dnsresolver.StatusWaiting}
	if service.syntheticResolver != nil {
		syntheticStatus = service.syntheticResolver.Status()
	}
	networkStatus := agentnetwork.Status{State: agentnetwork.StatusDisabled}
	if service.networkManager != nil {
		networkStatus = service.networkManager.Status()
	}
	gatewayStatus := tunnel.Status{State: tunnel.StatusDisabled}
	if service.gatewayTunnel != nil {
		gatewayStatus = service.gatewayTunnel.Status()
	}
	return ipc.AgentStatus{
		ServiceState:             string(serviceState),
		ServicePID:               identity.PID,
		ServiceUser:              identity.Username,
		ServiceUserSID:           identity.UserSID,
		AuthorizedUserSID:        authorizedUserSID,
		EnrollmentState:          enrollment.State,
		DeviceID:                 enrollment.DeviceID,
		DeviceIDSource:           enrollment.DeviceIDSource,
		ActiveUserSID:            enrollment.ActiveUserSID,
		KeyName:                  enrollment.KeyName,
		KeyExists:                enrollment.KeyExists,
		KeyProvider:              enrollment.KeyProvider,
		EnrollmentNonce:          enrollment.Nonce,
		CertificateSHA256:        enrollment.CertificateSHA256,
		CertificateExpiresAt:     enrollment.CertificateNotAfter,
		DevicePostureStatus:      posture.Status,
		DevicePostureCheckCount:  len(posture.Report.Checks),
		DevicePostureCollectedAt: posture.LastCollectedAt,
		DevicePostureReportedAt:  posture.LastReportedAt,
		DevicePostureLastError:   posture.LastError,
		DevicePostureReportError: posture.LastReportError,
		SessionState:             session.State,
		AccessTokenExpiresAt:     session.ExpiresAt,
		CatalogStatus:            catalogState.Status,
		CatalogVersion:           catalogState.Version,
		CatalogPolicyEpoch:       catalogState.PolicyEpoch,
		CatalogDNSSuffixCount:    len(catalogState.DNSSuffixes),
		CatalogResourceCount:     len(catalogState.Resources),
		CatalogLastSyncedAt:      catalogState.LastSyncedAt,
		CatalogNextSyncAt:        catalogState.NextSyncAt,
		CatalogNextRetryAt:       catalogState.NextRetryAt,
		CatalogLastError:         catalogState.LastError,
		SyntheticDNSStatus:       syntheticStatus.State,
		SyntheticDNSSuffixCount:  syntheticStatus.DNSSuffixCount,
		SyntheticResourceCount:   syntheticStatus.ResourceCount,
		SyntheticMappingCount:    syntheticStatus.ActiveMappingCount,
		SyntheticCGNATRange:      syntheticStatus.CGNATRange,
		SyntheticDNSUpdatedAt:    syntheticStatus.LastUpdatedAt,
		SyntheticDNSLastError:    syntheticStatus.LastError,
		NetworkStatus:            networkStatus.State,
		TUNName:                  networkStatus.TUNName,
		TUNIP:                    networkStatus.TUNIP,
		TUNNetmask:               networkStatus.TUNNetmask,
		TUNRouteCIDR:             networkStatus.CGNATRange,
		NetworkUpdatedAt:         networkStatus.UpdatedAt,
		NetworkPacketsRead:       networkStatus.PacketsRead,
		NetworkTCPPackets:        networkStatus.TCPPackets,
		NetworkMatchedPackets:    networkStatus.MatchedPackets,
		NetworkUnmatchedPackets:  networkStatus.UnmatchedPackets,
		NetworkDroppedPackets:    networkStatus.DroppedPackets,
		NetworkForwarderReady:    networkStatus.ForwarderConfigured,
		NetworkLastPacketAt:      networkStatus.LastPacketAt,
		NetworkLastPacketError:   networkStatus.LastPacketError,
		NetworkLastError:         networkStatus.LastError,
		GatewayTunnelStatus:      gatewayStatus.State,
		GatewayAddress:           gatewayStatus.GatewayAddress,
		GatewayTunnelConnectedAt: gatewayStatus.ConnectedAt,
		GatewayTunnelUpdatedAt:   gatewayStatus.UpdatedAt,
		GatewayTunnelLastError:   gatewayStatus.LastError,
		GatewayTunnelStreamCount: gatewayStatus.StreamCount,
		LastError:                enrollment.LastError,
		IdentityError:            enrollment.IdentityError,
		IdentityCheckedAt:        enrollment.IdentityCheckedAt,
		ReportedAt:               service.clock().UTC(),
	}
}
