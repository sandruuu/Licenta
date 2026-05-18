package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"agent/internal/service/catalog"
	"agent/internal/service/dnscontrol"
	"agent/internal/service/dnsresolver"
	servicestate "agent/internal/service/state"
	"agent/internal/shared/ipc"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (service *Service) syncDeviceCatalogIfReady(ctx context.Context) (bool, error) {
	if service.catalogClient == nil || service.dnsConfigurator == nil {
		return false, nil
	}
	now := service.clock().UTC()
	service.mu.RLock()
	enrolled := service.enrollment.State == ipc.EnrollmentStateEnrolled && strings.TrimSpace(service.enrollment.DeviceID) != ""
	accessToken := strings.TrimSpace(service.session.AccessToken)
	tokenExpiresAt := service.session.ExpiresAt
	currentVersion := strings.TrimSpace(service.catalog.Version)
	nextSyncAt := service.catalog.NextSyncAt
	nextRetryAt := service.catalog.NextRetryAt
	service.mu.RUnlock()
	if !enrolled {
		service.markCatalogWaitingForEnrollment()
		return false, nil
	}
	if accessToken == "" {
		service.markCatalogTokenRequired("access token is required")
		return false, nil
	}
	if !tokenExpiresAt.IsZero() && !tokenExpiresAt.After(now.Add(service.accessTokenExpirySkew)) {
		service.markSessionExpired("access token is expired or near expiry")
		service.markCatalogTokenRequired("access token is expired or near expiry")
		return false, nil
	}
	if !nextRetryAt.IsZero() && now.Before(nextRetryAt) {
		return false, nil
	}
	if !nextSyncAt.IsZero() && now.Before(nextSyncAt) {
		return false, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, service.postureReportTimeout)
		defer cancel()
	}
	catalogSnapshot, err := service.catalogClient.GetCatalog(ctx, accessToken, currentVersion)
	if err != nil {
		service.cacheCatalogError(err)
		return false, err
	}
	if catalogSnapshot.NotModified {
		service.markCatalogSynced(catalogSnapshot)
		service.persistCatalogCache(ctx)
		return false, nil
	}
	if err := service.dnsConfigurator.Apply(ctx, dnscontrol.Config{DNSSuffixes: catalogSnapshot.DNSSuffixes, DNSServer: service.dnsServer, HardenDoH: true}); err != nil {
		service.cacheCatalogError(err)
		return false, err
	}
	if err := service.applySyntheticCatalog(catalogSnapshot); err != nil {
		service.cacheCatalogError(err)
		return false, err
	}
	service.cacheCatalog(catalogSnapshot)
	service.persistCatalogCache(ctx)
	service.logger.Info("Device catalog applied", "suffix_count", len(catalogSnapshot.DNSSuffixes), "version", catalogSnapshot.Version)
	return true, nil
}

func (service *Service) cacheCatalog(catalogSnapshot catalog.Catalog) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.catalog.Version = strings.TrimSpace(catalogSnapshot.Version)
	service.catalog.PolicyEpoch = strings.TrimSpace(catalogSnapshot.PolicyEpoch)
	service.catalog.DNSSuffixes = append([]string(nil), catalogSnapshot.DNSSuffixes...)
	service.catalog.Resources = append([]catalog.Resource(nil), catalogSnapshot.Resources...)
	service.catalog.PosturePolicy = catalog.NormalizePosturePolicy(catalogSnapshot.PosturePolicy)
	service.catalog.TTLSeconds = catalogSnapshot.TTLSeconds
	service.catalog.ExpiresAt = service.catalogExpiresAt(catalogSnapshot.TTLSeconds)
	service.catalog.NextSyncAt = service.catalogNextSyncAt(catalogSnapshot.TTLSeconds)
	service.catalog.NextRetryAt = time.Time{}
	service.catalog.ConsecutiveFailures = 0
	service.catalog.Status = catalogStatusReady
	service.catalog.LastError = ""
	service.catalog.LastSyncedAt = service.clock().UTC()
}

func (service *Service) applySyntheticCatalog(catalogSnapshot catalog.Catalog) error {
	if service.syntheticResolver == nil {
		return nil
	}
	resources := make([]dnsresolver.Resource, 0, len(catalogSnapshot.Resources))
	for _, resource := range catalogSnapshot.Resources {
		resources = append(resources, dnsresolver.Resource{
			FQDN:       resource.FQDN,
			ResourceID: resource.ResourceID,
			Protocol:   resource.Protocol,
			Port:       resource.Port,
		})
	}
	return service.syntheticResolver.ApplyPolicy(dnsresolver.Policy{
		Version:     strings.TrimSpace(catalogSnapshot.Version),
		PolicyEpoch: strings.TrimSpace(catalogSnapshot.PolicyEpoch),
		DNSSuffixes: append([]string(nil), catalogSnapshot.DNSSuffixes...),
		Resources:   resources,
		TTLSeconds:  catalogSnapshot.TTLSeconds,
	})
}

func (service *Service) markCatalogSynced(catalogSnapshot catalog.Catalog) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if catalogSnapshot.TTLSeconds > 0 {
		service.catalog.TTLSeconds = catalogSnapshot.TTLSeconds
	}
	service.catalog.ExpiresAt = service.catalogExpiresAt(service.catalog.TTLSeconds)
	service.catalog.NextSyncAt = service.catalogNextSyncAt(service.catalog.TTLSeconds)
	service.catalog.NextRetryAt = time.Time{}
	service.catalog.ConsecutiveFailures = 0
	service.catalog.Status = catalogStatusReady
	service.catalog.LastError = ""
	service.catalog.LastSyncedAt = service.clock().UTC()
}

func (service *Service) cacheCatalogError(err error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if err != nil {
		service.catalog.LastError = err.Error()
	}
	if isCatalogTokenError(err) {
		service.catalog.Status = catalogStatusTokenRequired
		service.catalog.NextRetryAt = time.Time{}
		return
	}
	service.catalog.Status = catalogStatusError
	service.catalog.ConsecutiveFailures++
	service.catalog.NextRetryAt = service.clock().UTC().Add(catalogBackoff(service.catalogRetryBackoff, service.catalog.ConsecutiveFailures))
}

func (service *Service) markCatalogWaitingForEnrollment() {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.catalog.Status = catalogStatusWaitingForEnrollment
	service.catalog.NextRetryAt = time.Time{}
}

func (service *Service) markCatalogTokenRequired(message string) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.catalog.Status = catalogStatusTokenRequired
	service.catalog.LastError = strings.TrimSpace(message)
	service.catalog.NextRetryAt = time.Time{}
}

func (service *Service) catalogExpiresAt(ttlSeconds int) time.Time {
	if ttlSeconds <= 0 {
		return service.clock().UTC().Add(service.catalogCacheTTL)
	}
	return service.clock().UTC().Add(time.Duration(ttlSeconds) * time.Second)
}

func (service *Service) catalogNextSyncAt(ttlSeconds int) time.Time {
	if ttlSeconds <= 0 {
		return service.clock().UTC().Add(service.catalogInterval)
	}
	ttl := time.Duration(ttlSeconds) * time.Second
	if ttl > service.catalogInterval {
		ttl = service.catalogInterval
	}
	if ttl <= 0 {
		ttl = service.catalogCacheTTL
	}
	return service.clock().UTC().Add(ttl)
}

func catalogBackoff(backoff []time.Duration, failures int) time.Duration {
	if failures <= 0 || len(backoff) == 0 {
		return 0
	}
	index := failures - 1
	if index >= len(backoff) {
		index = len(backoff) - 1
	}
	return backoff[index]
}

func isCatalogTokenError(err error) bool {
	if err == nil {
		return false
	}
	code := status.Code(err)
	if code == codes.Unauthenticated || code == codes.PermissionDenied {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unauthenticated") || strings.Contains(message, "permissiondenied") || strings.Contains(message, "permission denied")
}

func (service *Service) persistedCatalogSnapshot() (servicestate.CatalogCache, bool) {
	service.mu.RLock()
	defer service.mu.RUnlock()
	if service.enrollment.State != ipc.EnrollmentStateEnrolled || strings.TrimSpace(service.enrollment.DeviceID) == "" {
		return servicestate.CatalogCache{}, false
	}
	if strings.TrimSpace(service.catalog.Version) == "" || len(service.catalog.DNSSuffixes) == 0 {
		return servicestate.CatalogCache{}, false
	}
	fetchedAt := service.catalog.LastSyncedAt
	if fetchedAt.IsZero() {
		fetchedAt = service.clock().UTC()
	}
	cache := servicestate.CatalogCache{
		Version:        servicestate.CatalogCacheFileVersion,
		DeviceID:       strings.TrimSpace(service.enrollment.DeviceID),
		CatalogVersion: strings.TrimSpace(service.catalog.Version),
		PolicyEpoch:    strings.TrimSpace(service.catalog.PolicyEpoch),
		DNSSuffixes:    append([]string(nil), service.catalog.DNSSuffixes...),
		Resources:      append([]catalog.Resource(nil), service.catalog.Resources...),
		PosturePolicy:  catalog.NormalizePosturePolicy(service.catalog.PosturePolicy),
		TTLSeconds:     service.catalog.TTLSeconds,
		FetchedAt:      fetchedAt,
		ExpiresAt:      service.catalog.ExpiresAt,
	}
	return cache, cache.Validate() == nil
}

func (service *Service) persistCatalogCache(ctx context.Context) {
	if service.catalogCacheStore == nil {
		return
	}
	cache, ok := service.persistedCatalogSnapshot()
	if !ok {
		return
	}
	if err := service.catalogCacheStore.Save(ctx, cache); err != nil {
		service.cacheCatalogError(fmt.Errorf("persist catalog cache: %w", err))
		service.logger.Warn("Failed to persist ZTNA Agent catalog cache", "error", err)
	}
}

func (service *Service) restoreCatalogCache(ctx context.Context) {
	if service.catalogCacheStore == nil || service.dnsConfigurator == nil {
		return
	}
	service.mu.RLock()
	enrolled := service.enrollment.State == ipc.EnrollmentStateEnrolled
	deviceID := strings.TrimSpace(service.enrollment.DeviceID)
	service.mu.RUnlock()
	if !enrolled || deviceID == "" {
		return
	}
	cache, err := service.catalogCacheStore.Load(ctx)
	if errors.Is(err, servicestate.ErrCatalogCacheNotFound) {
		return
	}
	if err != nil {
		service.cacheCatalogError(fmt.Errorf("load catalog cache: %w", err))
		service.logger.Warn("Failed to load ZTNA Agent catalog cache", "error", err)
		return
	}
	if strings.TrimSpace(cache.DeviceID) != deviceID {
		service.logger.Warn("Ignoring ZTNA Agent catalog cache for different device", "cache_device_id", cache.DeviceID, "device_id", deviceID)
		return
	}
	if err := service.dnsConfigurator.Apply(ctx, dnscontrol.Config{DNSSuffixes: cache.DNSSuffixes, DNSServer: service.dnsServer, HardenDoH: true}); err != nil {
		service.cacheCatalogError(fmt.Errorf("apply cached catalog DNS: %w", err))
		service.logger.Warn("Failed to apply cached ZTNA Agent catalog", "error", err)
		return
	}
	if err := service.applySyntheticCatalog(catalog.Catalog{Version: cache.CatalogVersion, PolicyEpoch: cache.PolicyEpoch, DNSSuffixes: cache.DNSSuffixes, Resources: cache.Resources, TTLSeconds: cache.TTLSeconds}); err != nil {
		service.cacheCatalogError(fmt.Errorf("apply cached synthetic DNS catalog: %w", err))
		service.logger.Warn("Failed to apply cached ZTNA Agent synthetic DNS catalog", "error", err)
		return
	}
	now := service.clock().UTC()
	statusValue := catalogStatusReady
	if !cache.ExpiresAt.IsZero() && !cache.ExpiresAt.After(now) {
		statusValue = catalogStatusStale
	}
	service.mu.Lock()
	service.catalog.Status = statusValue
	service.catalog.Version = strings.TrimSpace(cache.CatalogVersion)
	service.catalog.PolicyEpoch = strings.TrimSpace(cache.PolicyEpoch)
	service.catalog.DNSSuffixes = append([]string(nil), cache.DNSSuffixes...)
	service.catalog.Resources = append([]catalog.Resource(nil), cache.Resources...)
	service.catalog.PosturePolicy = catalog.NormalizePosturePolicy(cache.PosturePolicy)
	service.catalog.TTLSeconds = cache.TTLSeconds
	service.catalog.ExpiresAt = cache.ExpiresAt
	service.catalog.NextSyncAt = time.Time{}
	service.catalog.NextRetryAt = time.Time{}
	service.catalog.ConsecutiveFailures = 0
	service.catalog.LastError = ""
	service.catalog.LastSyncedAt = cache.FetchedAt
	service.mu.Unlock()
	service.logger.Info("ZTNA Agent catalog cache restored", "device_id", deviceID, "suffix_count", len(cache.DNSSuffixes), "version", cache.CatalogVersion, "status", statusValue)
}
