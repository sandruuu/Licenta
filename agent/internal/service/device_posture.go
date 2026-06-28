package service

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"agent/internal/service/usersession"
	"agent/internal/shared/ipc"
)

const localPostureRequiredDefaultStatus = ipc.DeviceDataStatusGood

func (service *Service) enforceLocalDevicePosture(ctx context.Context, report ipc.DeviceDataReport) {
	if service == nil || service.userSessions == nil || service.protectedResources == nil {
		return
	}
	active := service.userSessions.ActiveAuthenticatedSessions()
	if len(active) == 0 {
		service.clearLocalAccessSuspension()
		return
	}

	catalog, policy := catalogPolicyForLocalPosture(active)
	if len(policy.RequiredChecks) == 0 {
		if !service.clearLocalAccessSuspension() || len(catalog.Resources) == 0 {
			return
		}
		applyCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := service.protectedResources.ApplyCatalog(applyCtx, catalog); err != nil {
			service.logger.Warn("failed to restore protected resources after clearing local suspension", "error", err)
			service.markLocalAccessSuspended("protected resource catalog could not be restored")
			return
		}
		service.userSessions.SetAuthenticatedMessage("Authenticated")
		service.logger.Info("protected resources restored after clearing local suspension", "catalog_version", catalog.Version)
		return
	}

	allowed, reason := deviceDataSatisfiesPolicy(report, policy)
	if !allowed {
		if service.markLocalAccessSuspended(reason) {
			clearCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := service.protectedResources.Clear(clearCtx); err != nil {
				service.logger.Warn("failed to clear protected resources after local posture failure", "reason", reason, "error", err)
			}
			service.userSessions.SetAuthenticatedMessage("Protected resource access is paused because device posture no longer satisfies policy.")
			service.logger.Warn("protected resources paused locally because device posture failed", "reason", reason)
		}
		return
	}

	if !service.clearLocalAccessSuspension() || len(catalog.Resources) == 0 {
		return
	}
	applyCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := service.protectedResources.ApplyCatalog(applyCtx, catalog); err != nil {
		service.logger.Warn("failed to restore protected resources after device posture recovered", "error", err)
		service.markLocalAccessSuspended("protected resource catalog could not be restored")
		return
	}
	service.userSessions.SetAuthenticatedMessage("Device posture restored. Protected resource access is available.")
	service.logger.Info("protected resources restored locally after device posture recovered", "catalog_version", catalog.Version)
}

func (service *Service) pauseProtectedResourcesFromRemoteEvent(ctx context.Context, message string) {
	_ = ctx
	if service == nil || service.protectedResources == nil {
		return
	}
	if !service.markLocalAccessSuspended(firstNonEmptyServiceString(message, "device posture no longer satisfies policy")) {
		return
	}
	clearCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := service.protectedResources.Clear(clearCtx); err != nil {
		service.logger.Warn("failed to clear protected resources after PDP posture revocation", "error", err)
	}
}

func catalogPolicyForLocalPosture(sessions []usersession.AuthenticatedSession) (ipc.CatalogInfo, ipc.DeviceDataPolicy) {
	var selected ipc.CatalogInfo
	requiredChecks := map[string]string{}
	for _, session := range sessions {
		if len(selected.Resources) == 0 && len(session.Catalog.Resources) > 0 {
			selected = session.Catalog
		}
		status := normalizeDeviceDataStatus(session.Catalog.DeviceDataPolicy.RequiredCheckStatus)
		if status == "" {
			status = localPostureRequiredDefaultStatus
		}
		for _, check := range session.Catalog.DeviceDataPolicy.RequiredChecks {
			check = strings.TrimSpace(check)
			if check == "" {
				continue
			}
			requiredChecks[strings.ToLower(check)] = status
		}
	}
	policy := ipc.DeviceDataPolicy{RequiredCheckStatus: localPostureRequiredDefaultStatus}
	for check, status := range requiredChecks {
		policy.RequiredChecks = append(policy.RequiredChecks, check)
		if status != "" {
			policy.RequiredCheckStatus = status
		}
	}
	sort.Strings(policy.RequiredChecks)
	return selected, policy
}

func deviceDataSatisfiesPolicy(report ipc.DeviceDataReport, policy ipc.DeviceDataPolicy) (bool, string) {
	if len(policy.RequiredChecks) == 0 {
		return true, ""
	}
	requiredStatus := normalizeDeviceDataStatus(policy.RequiredCheckStatus)
	if requiredStatus == "" {
		requiredStatus = localPostureRequiredDefaultStatus
	}
	checks := map[string]string{}
	for _, check := range report.Checks {
		name := strings.ToLower(strings.TrimSpace(check.Name))
		if name == "" {
			continue
		}
		checks[name] = normalizeDeviceDataStatus(check.Status)
	}
	for _, required := range policy.RequiredChecks {
		requiredKey := strings.ToLower(strings.TrimSpace(required))
		if requiredKey == "" {
			continue
		}
		status := checks[requiredKey]
		if status == "" {
			return false, fmt.Sprintf("%s is not reported", required)
		}
		if status != requiredStatus {
			return false, fmt.Sprintf("%s is %s, required %s", required, status, requiredStatus)
		}
	}
	return true, ""
}

func normalizeDeviceDataStatus(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func (service *Service) markLocalAccessSuspended(reason string) bool {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "device posture no longer satisfies policy"
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.localAccess.Suspended && service.localAccess.Reason == reason {
		return false
	}
	service.localAccess = localAccessState{Suspended: true, Reason: reason, UpdatedAt: service.clock().UTC()}
	return true
}

func (service *Service) clearLocalAccessSuspension() bool {
	service.mu.Lock()
	defer service.mu.Unlock()
	if !service.localAccess.Suspended {
		return false
	}
	service.localAccess = localAccessState{}
	return true
}
