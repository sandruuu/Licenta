package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"agent/internal/service/catalog"
)

const (
	CatalogCacheFileVersion = 1
	defaultCatalogCacheName = "agent-catalog-cache.json"
)

var ErrCatalogCacheNotFound = errors.New("catalog cache not found")

type CatalogCacheStore interface {
	Load(context.Context) (CatalogCache, error)
	Save(context.Context, CatalogCache) error
}

type CatalogCache struct {
	Version        int                   `json:"version"`
	DeviceID       string                `json:"device_id"`
	CatalogVersion string                `json:"catalog_version"`
	PolicyEpoch    string                `json:"policy_epoch,omitempty"`
	DNSSuffixes    []string              `json:"dns_suffixes"`
	Resources      []catalog.Resource    `json:"resources,omitempty"`
	PosturePolicy  catalog.PosturePolicy `json:"posture_policy,omitempty"`
	TTLSeconds     int                   `json:"ttl_seconds,omitempty"`
	FetchedAt      time.Time             `json:"fetched_at"`
	ExpiresAt      time.Time             `json:"expires_at,omitempty"`
	UpdatedAt      time.Time             `json:"updated_at"`
}

type CatalogCacheFileStore struct {
	path  string
	clock func() time.Time
}

func NewDefaultCatalogCacheStore(clock func() time.Time) CatalogCacheStore {
	return NewCatalogCacheFileStore(defaultCatalogCachePath(), clock)
}

func NewCatalogCacheFileStore(path string, clock func() time.Time) *CatalogCacheFileStore {
	if clock == nil {
		clock = time.Now
	}
	return &CatalogCacheFileStore{path: filepath.Clean(strings.TrimSpace(path)), clock: clock}
}

func defaultCatalogCachePath() string {
	return filepath.Join(defaultEnrollmentStateDir(), defaultCatalogCacheName)
}

func (store *CatalogCacheFileStore) Load(ctx context.Context) (CatalogCache, error) {
	if store == nil || strings.TrimSpace(store.path) == "" {
		return CatalogCache{}, ErrCatalogCacheNotFound
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return CatalogCache{}, ctx.Err()
	default:
	}
	data, err := os.ReadFile(store.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return CatalogCache{}, ErrCatalogCacheNotFound
		}
		return CatalogCache{}, fmt.Errorf("read catalog cache: %w", err)
	}
	var cache CatalogCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return CatalogCache{}, fmt.Errorf("decode catalog cache: %w", err)
	}
	if err := cache.Validate(); err != nil {
		return CatalogCache{}, err
	}
	cache.DNSSuffixes = catalog.NormalizeSuffixes(cache.DNSSuffixes)
	cache.Resources = catalog.NormalizeResources(cache.Resources)
	cache.PosturePolicy = catalog.NormalizePosturePolicy(cache.PosturePolicy)
	return cache, nil
}

func (store *CatalogCacheFileStore) Save(ctx context.Context, cache CatalogCache) error {
	if store == nil || strings.TrimSpace(store.path) == "" {
		return errors.New("catalog cache path is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	cache.Version = CatalogCacheFileVersion
	cache.UpdatedAt = store.clock().UTC()
	cache.DNSSuffixes = catalog.NormalizeSuffixes(cache.DNSSuffixes)
	cache.Resources = catalog.NormalizeResources(cache.Resources)
	cache.PosturePolicy = catalog.NormalizePosturePolicy(cache.PosturePolicy)
	if err := cache.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("encode catalog cache: %w", err)
	}
	data = append(data, '\n')
	dir := filepath.Dir(store.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create catalog cache directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".agent-catalog-cache-*.tmp")
	if err != nil {
		return fmt.Errorf("create catalog cache temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("harden catalog cache temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write catalog cache temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync catalog cache temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close catalog cache temp file: %w", err)
	}
	if err := os.Rename(tmpName, store.path); err != nil {
		return fmt.Errorf("replace catalog cache file: %w", err)
	}
	return nil
}

func (cache CatalogCache) Validate() error {
	if cache.Version != CatalogCacheFileVersion {
		return fmt.Errorf("unsupported catalog cache version %d", cache.Version)
	}
	if strings.TrimSpace(cache.DeviceID) == "" {
		return errors.New("catalog cache device_id is required")
	}
	if strings.TrimSpace(cache.CatalogVersion) == "" {
		return errors.New("catalog cache version is required")
	}
	if len(catalog.NormalizeSuffixes(cache.DNSSuffixes)) == 0 {
		return errors.New("catalog cache requires at least one DNS suffix")
	}
	if cache.TTLSeconds < 0 {
		return errors.New("catalog cache ttl_seconds must not be negative")
	}
	if cache.FetchedAt.IsZero() {
		return errors.New("catalog cache fetched_at is required")
	}
	return nil
}
