package service

import (
	"context"
	"strings"
	"time"

	"agent/internal/shared/ipc"
)

const (
	connectionConnected  = "connected"
	connectionUnenrolled = "unenrolled"
	connectionPending    = "enrolling"
)

func (service *Service) dashboard(ctx context.Context) ipc.AgentDashboard {
	service.enrollment.Refresh(ctx)
	status := service.status()
	peer, _ := ipc.PeerIdentityFromContext(ctx)
	userSession := service.userSessions.DashboardSnapshot(peer)
	authenticated := strings.EqualFold(userSession.UserSession.State, ipc.UserSessionStateAuthenticated)
	now := service.clock().UTC()
	catalog := ipc.CatalogInfo{}
	deviceData := ipc.DeviceDataReport{}
	if authenticated {
		catalog = userSession.Catalog
		deviceData = service.dashboardDeviceData(ctx, status)
	} else {
		status.DeviceDataStatus = ""
		status.DeviceDataCheckCount = 0
		status.DeviceDataCollectedAt = time.Time{}
		status.DeviceDataLastError = ""
		if status.EnrollmentState == ipc.EnrollmentStateEnrolled &&
			strings.EqualFold(userSession.UserSession.State, ipc.UserSessionStateSignedOut) &&
			strings.TrimSpace(userSession.UserSession.Message) == "" {
			userSession.UserSession.Message = service.signedOutAccessPrompt(now)
		}
	}
	return ipc.AgentDashboard{
		Connection:  dashboardConnection(status),
		Status:      status,
		Enrollment:  dashboardEnrollment(status),
		UserSession: userSession.UserSession,
		Catalog:     catalog,
		DeviceData:  deviceData,
		ReportedAt:  now,
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

func (service *Service) dashboardDeviceData(_ context.Context, status ipc.AgentStatus) ipc.DeviceDataReport {
	deviceData := service.cachedDeviceDataReport()
	if len(deviceData.Checks) == 0 {
		return unavailableDeviceDataReport(status, nil)
	}
	return deviceData
}

func unavailableDeviceDataReport(status ipc.AgentStatus, err error) ipc.DeviceDataReport {
	description := "Device data is not available from the service"
	details := map[string]string{}
	if err != nil {
		details["Reason"] = err.Error()
	}
	return ipc.DeviceDataReport{
		Hostname:    "Unknown",
		OS:          "Unknown",
		CollectedAt: status.ReportedAt,
		Checks: []ipc.DeviceDataCheck{{
			Name:        "Device Data",
			Status:      ipc.DeviceDataStatusUnavailable,
			Description: description,
			Details:     details,
		}},
	}
}
