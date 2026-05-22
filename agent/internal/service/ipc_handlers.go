package service

import (
	"context"
	"errors"
	"strings"
	"time"

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
	case ipc.OperationGetDeviceData:
		var payload ipc.DeviceDataRequest
		if err := ipc.DecodeBody(request.Body, &payload); err != nil {
			return ipc.NewErrorResponse(request.ID, ipc.ErrorCodeInvalidRequest, err.Error()), nil
		}
		report, code, err := service.deviceDataReport(ctx)
		if err != nil {
			return ipc.NewErrorResponse(request.ID, code, err.Error()), nil
		}
		return ipc.NewResponse(request.ID, report)
	case ipc.OperationStartEnrollmentInteractive:
		var payload ipc.StartEnrollmentInteractiveRequest
		if err := ipc.DecodeBody(request.Body, &payload); err != nil {
			return ipc.NewErrorResponse(request.ID, ipc.ErrorCodeInvalidRequest, err.Error()), nil
		}
		response, code, err := service.enrollment.StartInteractive(ctx)
		if err != nil {
			return ipc.NewErrorResponse(request.ID, code, err.Error()), nil
		}
		return ipc.NewResponse(request.ID, response)
	case ipc.OperationStartUserLoginInteractive:
		var payload ipc.StartUserLoginInteractiveRequest
		if err := ipc.DecodeBody(request.Body, &payload); err != nil {
			return ipc.NewErrorResponse(request.ID, ipc.ErrorCodeInvalidRequest, err.Error()), nil
		}
		peer, ok := ipc.PeerIdentityFromContext(ctx)
		if !ok {
			return ipc.NewErrorResponse(request.ID, ipc.ErrorCodeInvalidRequest, "verified IPC peer identity is required"), nil
		}
		response, code, err := service.userSessions.StartInteractive(ctx, peer)
		if err != nil {
			return ipc.NewErrorResponse(request.ID, code, err.Error()), nil
		}
		return ipc.NewResponse(request.ID, response)
	case ipc.OperationLogoutUserSession:
		var payload ipc.LogoutUserSessionRequest
		if err := ipc.DecodeBody(request.Body, &payload); err != nil {
			return ipc.NewErrorResponse(request.ID, ipc.ErrorCodeInvalidRequest, err.Error()), nil
		}
		peer, ok := ipc.PeerIdentityFromContext(ctx)
		if !ok {
			return ipc.NewErrorResponse(request.ID, ipc.ErrorCodeInvalidRequest, "verified IPC peer identity is required"), nil
		}
		response, code, err := service.userSessions.Logout(ctx, peer)
		if err != nil {
			return ipc.NewErrorResponse(request.ID, code, err.Error()), nil
		}
		return ipc.NewResponse(request.ID, response)
	default:
		return ipc.NewErrorResponse(request.ID, ipc.ErrorCodeUnsupported, "unsupported IPC operation"), nil
	}
}

func (service *Service) ping(payload ipc.PingRequest) ipc.PingResponse {
	identity := currentProcessIdentity()
	message := strings.TrimSpace(payload.Message)
	if message == "" {
		message = "ping"
	}
	return ipc.PingResponse{
		Message:        "pong from service",
		Echo:           message,
		Protocol:       ipc.ProtocolVersion,
		PipeName:       ipc.PipePath(),
		ServiceState:   string(service.State()),
		ServicePID:     identity.PID,
		ServiceUser:    identity.Username,
		ServiceUserSID: identity.UserSID,
		ReceivedAt:     time.Now().UTC(),
	}
}

func (service *Service) status() ipc.AgentStatus {
	identity := currentProcessIdentity()
	service.mu.RLock()
	deviceData := service.deviceData
	serviceState := service.state
	service.mu.RUnlock()
	enrollment := service.enrollment.Snapshot()
	return ipc.AgentStatus{
		ServiceState:          string(serviceState),
		ServicePID:            identity.PID,
		ServiceUser:           identity.Username,
		ServiceUserSID:        identity.UserSID,
		EnrollmentState:       enrollment.State,
		EnrollmentDeviceID:    enrollment.DeviceID,
		EnrollmentLastError:   enrollment.LastError,
		DeviceDataStatus:      deviceData.Status,
		DeviceDataCheckCount:  len(deviceData.Report.Checks),
		DeviceDataCollectedAt: deviceData.LastCollectedAt,
		DeviceDataLastError:   deviceData.LastError,
		ReportedAt:            service.clock().UTC(),
	}
}
