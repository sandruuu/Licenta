package service

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"ztna.local/agent/internal/catalog"
	"ztna.local/agent/internal/deviceidentity"
	"ztna.local/agent/internal/ipc"
)

const (
	accessEventLimit        = 50
	dashboardPostureMaxAge  = 2 * time.Minute
	connectionConnected     = "connected"
	connectionDisconnected  = "disconnected"
	connectionUnenrolled    = "unenrolled"
	resourceStatusAvailable = "available"
)

func (service *Service) dashboard(ctx context.Context) ipc.AgentDashboard {
	status := service.status()
	posture := service.dashboardPosture(ctx, status)
	resources := service.catalogResources()
	activeSessions := service.activeSessions()
	accessEvents := service.accessEvents(status)
	return ipc.AgentDashboard{
		Connection:     dashboardConnection(status),
		Status:         status,
		Enrollment:     dashboardEnrollment(status),
		Certificate:    service.certificateInfo(ctx, status),
		User:           service.authenticatedUser(status),
		Posture:        posture,
		Resources:      resources,
		ActiveSessions: activeSessions,
		AccessEvents:   accessEvents,
		ReportedAt:     service.clock().UTC(),
	}
}

func (service *Service) catalogResourcesResponse() ipc.CatalogResourcesResponse {
	return ipc.CatalogResourcesResponse{Resources: service.catalogResources(), ReportedAt: service.clock().UTC()}
}

func (service *Service) activeSessionsResponse() ipc.ActiveSessionsResponse {
	return ipc.ActiveSessionsResponse{Sessions: service.activeSessions(), ReportedAt: service.clock().UTC()}
}

func (service *Service) accessEventsResponse() ipc.AccessEventsResponse {
	return ipc.AccessEventsResponse{Events: service.accessEvents(service.status()), ReportedAt: service.clock().UTC()}
}

func dashboardConnection(status ipc.AgentStatus) ipc.DashboardConnection {
	connection := ipc.DashboardConnection{
		ServiceState: status.ServiceState,
		SessionState: status.SessionState,
		CatalogState: status.CatalogStatus,
		NetworkState: status.NetworkStatus,
	}
	if status.EnrollmentState != ipc.EnrollmentStateEnrolled {
		connection.State = connectionUnenrolled
		connection.Message = "Device enrollment is required before resource access can start"
		return connection
	}
	if strings.EqualFold(status.ServiceState, string(StateRunning)) && strings.EqualFold(status.SessionState, sessionStatusReady) {
		connection.State = connectionConnected
		connection.Message = "Service, device identity, and user session are available"
		return connection
	}
	connection.State = connectionDisconnected
	if status.SessionState == sessionStatusMissing || status.SessionState == sessionStatusExpired || status.SessionState == sessionStatusRejected {
		connection.Message = "User session is not ready"
	} else {
		connection.Message = "Agent service is not fully connected"
	}
	return connection
}

func dashboardEnrollment(status ipc.AgentStatus) ipc.EnrollmentInfo {
	return ipc.EnrollmentInfo{
		State:          status.EnrollmentState,
		DeviceID:       status.DeviceID,
		DeviceIDSource: status.DeviceIDSource,
		ActiveUserSID:  status.ActiveUserSID,
		KeyName:        status.KeyName,
		KeyExists:      status.KeyExists,
		KeyProvider:    status.KeyProvider,
		Nonce:          status.EnrollmentNonce,
		LastError:      firstNonEmpty(status.LastError, status.IdentityError),
	}
}

func (service *Service) authenticatedUser(status ipc.AgentStatus) ipc.AuthenticatedUser {
	service.mu.RLock()
	email := strings.TrimSpace(service.session.UserEmail)
	userSID := firstNonEmpty(service.session.UserSID, status.ActiveUserSID, status.AuthorizedUserSID)
	service.mu.RUnlock()
	return ipc.AuthenticatedUser{
		UserSID:              userSID,
		AuthorizedUserSID:    status.AuthorizedUserSID,
		Email:                email,
		SessionState:         status.SessionState,
		AccessTokenExpiresAt: status.AccessTokenExpiresAt,
	}
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
		DeviceID:    status.DeviceID,
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

func (service *Service) certificateInfo(ctx context.Context, status ipc.AgentStatus) ipc.CertificateInfo {
	info := ipc.CertificateInfo{SHA256: status.CertificateSHA256, ExpiresAt: status.CertificateExpiresAt}
	if service.certificateLoader == nil || strings.TrimSpace(status.DeviceID) == "" {
		info.Valid = certificateTimeValid(service.clock, info.NotBefore, info.ExpiresAt)
		return info
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultCertificateRenewalTimeout)
		defer cancel()
	}
	certificate, err := service.certificateLoader(ctx, deviceidentity.MachineCertificateOptions{
		DeviceID:    status.DeviceID,
		KeyName:     status.KeyName,
		KeyProvider: status.KeyProvider,
		Clock:       service.clock,
	})
	if err != nil {
		info.LastError = err.Error()
		info.Valid = certificateTimeValid(service.clock, info.NotBefore, info.ExpiresAt)
		return info
	}
	leaf, err := leafCertificate(certificate.Leaf, certificate.Certificate)
	if err != nil {
		info.LastError = err.Error()
		info.Valid = certificateTimeValid(service.clock, info.NotBefore, info.ExpiresAt)
		return info
	}
	info.Subject = leaf.Subject.String()
	info.Issuer = leaf.Issuer.String()
	if leaf.SerialNumber != nil {
		info.SerialNumber = leaf.SerialNumber.String()
	}
	info.NotBefore = leaf.NotBefore.UTC()
	info.ExpiresAt = leaf.NotAfter.UTC()
	if info.SHA256 == "" && len(certificate.Certificate) > 0 {
		digest := sha256.Sum256(certificate.Certificate[0])
		info.SHA256 = hex.EncodeToString(digest[:])
	}
	info.Valid = certificateTimeValid(service.clock, info.NotBefore, info.ExpiresAt)
	return info
}

func leafCertificate(leaf *x509.Certificate, chain [][]byte) (*x509.Certificate, error) {
	if leaf != nil {
		return leaf, nil
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("certificate chain is empty")
	}
	parsed, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, fmt.Errorf("parse endpoint certificate: %w", err)
	}
	return parsed, nil
}

func certificateTimeValid(clock func() time.Time, notBefore, notAfter time.Time) bool {
	if notAfter.IsZero() {
		return false
	}
	now := time.Now().UTC()
	if clock != nil {
		now = clock().UTC()
	}
	if !notBefore.IsZero() && now.Before(notBefore.UTC()) {
		return false
	}
	return now.Before(notAfter.UTC())
}

func (service *Service) catalogResources() []ipc.CatalogResource {
	service.mu.RLock()
	resources := append([]catalog.Resource(nil), service.catalog.Resources...)
	status := service.catalog.Status
	updatedAt := service.catalog.LastSyncedAt
	service.mu.RUnlock()
	result := make([]ipc.CatalogResource, 0, len(resources))
	for _, resource := range resources {
		result = append(result, ipc.CatalogResource{
			FQDN:       resource.FQDN,
			ResourceID: resource.ResourceID,
			Protocol:   resource.Protocol,
			Port:       resource.Port,
			Status:     resourceDisplayStatus(status),
			UpdatedAt:  updatedAt,
		})
	}
	return result
}

func resourceDisplayStatus(catalogStatus string) string {
	if catalogStatus == catalogStatusReady || catalogStatus == catalogStatusStale {
		return resourceStatusAvailable
	}
	return catalogStatus
}

func (service *Service) activeSessions() []ipc.ActiveSession {
	if service.relayForwarder == nil {
		return []ipc.ActiveSession{}
	}
	return service.relayForwarder.Sessions()
}

func (service *Service) accessEvents(status ipc.AgentStatus) []ipc.AccessEvent {
	service.mu.RLock()
	stored := append([]ipc.AccessEvent(nil), service.accessEventHistory...)
	service.mu.RUnlock()
	events := make([]ipc.AccessEvent, 0, len(stored)+4)
	now := service.clock().UTC()
	if status.EnrollmentState != ipc.EnrollmentStateEnrolled {
		events = append(events, syntheticAccessEvent("local-enrollment", "deny", "Device is not enrolled", "local_enrollment", now, map[string]string{"state": string(status.EnrollmentState)}))
	}
	if status.SessionState == sessionStatusMissing || status.SessionState == sessionStatusExpired || status.SessionState == sessionStatusRejected {
		reason := "User access token is not available"
		if status.SessionState == sessionStatusExpired {
			reason = "User access token has expired"
		} else if status.SessionState == sessionStatusRejected {
			reason = "User access token was rejected by the service"
		}
		events = append(events, syntheticAccessEvent("local-session", "deny", reason, "local_session", now, map[string]string{"state": status.SessionState}))
	}
	if status.CatalogStatus == catalogStatusTokenRequired || status.CatalogStatus == catalogStatusError {
		reason := firstNonEmpty(status.CatalogLastError, "Catalog is not ready for resource access")
		events = append(events, syntheticAccessEvent("local-catalog", "deny", reason, "local_catalog", now, map[string]string{"state": status.CatalogStatus}))
	}
	if status.NetworkMatchedPackets > 0 && !status.NetworkForwarderReady {
		events = append(events, syntheticAccessEvent("local-forwarder", "deny", "Gateway stream forwarder is not configured yet", "local_network", firstNonZeroTime(status.NetworkLastPacketAt, now), map[string]string{"matched_packets": fmt.Sprint(status.NetworkMatchedPackets)}))
	}
	if status.NetworkUnmatchedPackets > 0 {
		events = append(events, syntheticAccessEvent("local-unmatched", "deny", "Synthetic destination or port did not match a catalog resource", "local_network", firstNonZeroTime(status.NetworkLastPacketAt, now), map[string]string{"unmatched_packets": fmt.Sprint(status.NetworkUnmatchedPackets)}))
	}
	events = append(events, stored...)
	sort.SliceStable(events, func(left, right int) bool {
		return events[left].OccurredAt.After(events[right].OccurredAt)
	})
	if len(events) > accessEventLimit {
		events = events[:accessEventLimit]
	}
	return events
}

func (service *Service) setSessionUserEmail(email string) {
	if strings.TrimSpace(email) == "" {
		return
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	service.session.UserEmail = strings.TrimSpace(email)
}

func (service *Service) appendAccessEventLocked(event ipc.AccessEvent) {
	if strings.TrimSpace(event.Reason) == "" {
		event.Reason = "Access was denied by the local Agent state"
	}
	if strings.TrimSpace(event.Decision) == "" {
		event.Decision = "deny"
	}
	if strings.TrimSpace(event.Source) == "" {
		event.Source = "local_agent"
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = service.clock().UTC()
	}
	if strings.TrimSpace(event.ID) == "" {
		event.ID = fmt.Sprintf("local-%d", event.OccurredAt.UnixNano())
	}
	service.accessEventHistory = append(service.accessEventHistory, event)
	if len(service.accessEventHistory) > accessEventLimit {
		service.accessEventHistory = service.accessEventHistory[len(service.accessEventHistory)-accessEventLimit:]
	}
}

func (service *Service) recordAccessEvent(event ipc.AccessEvent) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.appendAccessEventLocked(event)
}

func syntheticAccessEvent(id, decision, reason, source string, occurredAt time.Time, details map[string]string) ipc.AccessEvent {
	return ipc.AccessEvent{ID: id, Decision: decision, Reason: reason, Source: source, Details: details, OccurredAt: occurredAt.UTC()}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstNonZeroTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value.UTC()
		}
	}
	return time.Time{}
}
