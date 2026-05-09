// Package catalog implements device-side FQDN catalog synchronization.
//
// The catalog is a list of protected FQDNs that the service intercepts via
// DNS and WFP. It is downloaded from Cloud using device mTLS and cached
// locally with versioning. The catalog MUST remain private to the privileged
// service process — it is never exposed to the tray or any IPC consumer.
package catalog

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// CatalogEntry represents a single protected FQDN from the Cloud PDP.
type CatalogEntry struct {
	FQDN       string `json:"fqdn"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
	ResourceID string `json:"resource_id"`
}

// Catalog is a versioned snapshot of protected FQDNs.
type Catalog struct {
	Version   string         `json:"version"`
	Entries   []CatalogEntry `json:"entries"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// CatalogMeta contains version metadata safe to expose over IPC.
// It intentionally excludes the FQDN list.
type CatalogMeta struct {
	Version    string    `json:"version"`
	EntryCount int       `json:"entry_count"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Meta returns the metadata summary of a catalog snapshot.
func (c *Catalog) Meta() CatalogMeta {
	if c == nil {
		return CatalogMeta{}
	}
	return CatalogMeta{
		Version:    c.Version,
		EntryCount: len(c.Entries),
		UpdatedAt:  c.UpdatedAt,
	}
}

// SyncClient abstracts the transport used to fetch the catalog from Cloud.
// The current implementation uses HTTP/2 + mTLS; a future gRPC client
// can implement this interface without changing the trust boundary.
type SyncClient interface {
	// FetchCatalog retrieves the latest catalog from Cloud.
	// If currentVersion matches the server version, it returns nil catalog
	// and nil error (no update available).
	FetchCatalog(ctx context.Context, currentVersion string) (*Catalog, error)
}

// SyncerConfig configures the catalog sync loop.
type SyncerConfig struct {
	Client   SyncClient
	Cache    *Cache
	Interval time.Duration
	Logger   *slog.Logger
	OnUpdate func(CatalogMeta) // called with metadata only — no FQDNs
}

// Syncer orchestrates periodic catalog synchronization.
// It owns the authoritative catalog state inside the service process.
type Syncer struct {
	mu      sync.RWMutex
	config  SyncerConfig
	catalog *Catalog
	logger  *slog.Logger
}

// NewSyncer creates a catalog syncer. The syncer loads the local cache
// on creation so that DNS/WFP have entries available before the first
// network sync completes.
func NewSyncer(config SyncerConfig) *Syncer {
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	interval := config.Interval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	config.Interval = interval
	config.Logger = logger

	syncer := &Syncer{
		config: config,
		logger: logger,
	}

	// Load cached catalog for offline resilience.
	if config.Cache != nil {
		if cached, err := config.Cache.Load(); err == nil && cached != nil {
			syncer.catalog = cached
			logger.Info("Loaded cached device catalog",
				"version", cached.Version,
				"entries", len(cached.Entries),
				"updated_at", cached.UpdatedAt.Format(time.RFC3339))
		}
	}

	return syncer
}

// Run starts the periodic sync loop. It blocks until ctx is cancelled.
func (s *Syncer) Run(ctx context.Context) {
	// Immediate sync on start.
	s.SyncNow(ctx)

	ticker := time.NewTicker(s.config.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.SyncNow(ctx)
		}
	}
}

// SyncNow performs an immediate catalog synchronization attempt.
func (s *Syncer) SyncNow(ctx context.Context) {
	s.sync(ctx)
}

// Version returns the current catalog version string.
func (s *Syncer) Version() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.catalog == nil {
		return ""
	}
	return s.catalog.Version
}

// EntryCount returns the number of entries in the current catalog.
func (s *Syncer) EntryCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.catalog == nil {
		return 0
	}
	return len(s.catalog.Entries)
}

// Meta returns version metadata safe for IPC exposure.
func (s *Syncer) Meta() CatalogMeta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.catalog == nil {
		return CatalogMeta{}
	}
	return s.catalog.Meta()
}

// Lookup finds a catalog entry by FQDN. This is used internally by
// DNS interceptor and WFP redirect — never exposed over IPC.
func (s *Syncer) Lookup(fqdn string) (CatalogEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.catalog == nil {
		return CatalogEntry{}, false
	}
	for _, entry := range s.catalog.Entries {
		if entry.FQDN == fqdn {
			return entry, true
		}
	}
	return CatalogEntry{}, false
}

// AllEntries returns a copy of all catalog entries. This is used
// internally by DNS/WFP modules — never exposed over IPC.
func (s *Syncer) AllEntries() []CatalogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.catalog == nil {
		return nil
	}
	entries := make([]CatalogEntry, len(s.catalog.Entries))
	copy(entries, s.catalog.Entries)
	return entries
}

func (s *Syncer) sync(ctx context.Context) {
	if s.config.Client == nil {
		return
	}
	currentVersion := s.Version()
	catalog, err := s.config.Client.FetchCatalog(ctx, currentVersion)
	if err != nil {
		if ctx.Err() == nil {
			s.logger.Error("Device catalog sync failed", "error", err)
		}
		return
	}
	if catalog == nil {
		// 304 — no update.
		s.logger.Debug("Device catalog unchanged", "version", currentVersion)
		return
	}

	s.mu.Lock()
	s.catalog = catalog
	s.mu.Unlock()

	s.logger.Info("Device catalog updated",
		"version", catalog.Version,
		"entries", len(catalog.Entries))

	// Persist to local cache.
	if s.config.Cache != nil {
		if err := s.config.Cache.Save(catalog); err != nil {
			s.logger.Error("Device catalog cache write failed", "error", err)
		}
	}

	// Notify service with metadata only — no FQDNs.
	if s.config.OnUpdate != nil {
		s.config.OnUpdate(catalog.Meta())
	}
}
