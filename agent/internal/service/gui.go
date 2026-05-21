package service

import (
	"context"
	"time"

	"agent/internal/shared/ipc"
)

const (
	dashboardPostureMaxAge = 2 * time.Minute
	connectionConnected    = "connected"
	connectionUnenrolled   = "unenrolled"
	connectionPending      = "enrolling"
)

func (service *Service) dashboard(ctx context.Context) ipc.AgentDashboard {
	status := service.status()
	posture := service.dashboardPosture(ctx, status)
	peer, _ := ipc.PeerIdentityFromContext(ctx)
	userSession := service.userSessions.Snapshot(peer)
	return ipc.AgentDashboard{
		Connection:  dashboardConnection(status),
		Status:      status,
		Enrollment:  dashboardEnrollment(status),
		UserSession: userSession.UserSession,
		Catalog:     userSession.Catalog,
		Posture:     posture,
		ReportedAt:  service.clock().UTC(),
	}
}

func dashboardConnection(status ipc.AgentStatus) ipc.DashboardConnection {
	connection := ipc.DashboardConnection{
		ServiceState: status.ServiceState,
	}
	if status.EnrollmentState == ipc.EnrollmentStateEnrolled {
		connection.State = connectionConnected
		connection.Message = "Device enrolled"
		return connection
	}
	if status.EnrollmentState == ipc.EnrollmentStateEnrolling {
		connection.State = connectionPending
		connection.Message = "Device enrollment is in progress"
		return connection
	}
	connection.State = connectionUnenrolled
	connection.Message = "Device enrollment is required before resource access can start"
	return connection
}

func dashboardEnrollment(status ipc.AgentStatus) ipc.EnrollmentInfo {
	return ipc.EnrollmentInfo{State: status.EnrollmentState, DeviceID: status.EnrollmentDeviceID, LastError: status.EnrollmentLastError}
}

func (service *Service) dashboardPosture(ctx context.Context, status ipc.AgentStatus) ipc.DevicePostureReport {
	posture := service.cachedPostureReport()
	stale := status.DevicePostureCollectedAt.IsZero() || service.clock().UTC().Sub(status.DevicePostureCollectedAt) > dashboardPostureMaxAge
	if service.postureCollector != nil && (len(posture.Checks) == 0 || stale) {
		if report, _, err := service.devicePosture(ctx); err == nil {
			return report
		} else if len(posture.Checks) == 0 {
			return unavailablePostureReport(status, err)
		}
	}
	if len(posture.Checks) == 0 {
		return unavailablePostureReport(status, nil)
	}
	return posture
}

func unavailablePostureReport(status ipc.AgentStatus, err error) ipc.DevicePostureReport {
	description := "Device posture is not available from the service"
	details := map[string]string{}
	if err != nil {
		details["Reason"] = err.Error()
	}
	return ipc.DevicePostureReport{
		Hostname:    "Unknown",
		OS:          "Unknown",
		CollectedAt: status.ReportedAt,
		Checks: []ipc.DevicePostureCheck{{
			Name:        "Device Posture",
			Status:      ipc.DevicePostureStatusUnavailable,
			Description: description,
			Details:     details,
		}},
	}
}
