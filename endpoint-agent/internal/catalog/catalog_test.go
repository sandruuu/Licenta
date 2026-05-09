package catalog

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- Cache tests ---

func TestCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cache := NewCache(dir)

	original := &Catalog{
		Version: "v1-abc",
		Entries: []CatalogEntry{
			{FQDN: "jira.corp.internal", Port: 443, Protocol: "https", ResourceID: "res-1"},
			{FQDN: "gitlab.corp.internal", Port: 443, Protocol: "https", ResourceID: "res-2"},
		},
		UpdatedAt: time.Now().UTC().Truncate(time.Second),
	}

	if err := cache.Save(original); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := cache.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded == nil {
		t.Fatal("Load returned nil")
	}
	if loaded.Version != original.Version {
		t.Fatalf("version = %q, want %q", loaded.Version, original.Version)
	}
	if len(loaded.Entries) != len(original.Entries) {
		t.Fatalf("entries = %d, want %d", len(loaded.Entries), len(original.Entries))
	}
	for i, entry := range loaded.Entries {
		if entry.FQDN != original.Entries[i].FQDN {
			t.Fatalf("entry[%d].FQDN = %q, want %q", i, entry.FQDN, original.Entries[i].FQDN)
		}
	}
}

func TestCacheLoadMissing(t *testing.T) {
	dir := t.TempDir()
	cache := NewCache(dir)

	loaded, err := cache.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded != nil {
		t.Fatal("expected nil for missing cache")
	}
}

func TestCacheAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	cache := NewCache(dir)

	catalog := &Catalog{Version: "v1", Entries: []CatalogEntry{{FQDN: "a.test", Port: 80}}}
	if err := cache.Save(catalog); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Temp file should not exist after save.
	tmpPath := cache.Path() + ".tmp"
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatalf("temp file should not exist after save: %v", err)
	}

	// Main file should exist and be valid JSON.
	data, err := os.ReadFile(cache.Path())
	if err != nil {
		t.Fatalf("read cache file: %v", err)
	}
	var decoded Catalog
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("cache file is not valid JSON: %v", err)
	}
	if decoded.Version != "v1" {
		t.Fatalf("version = %q, want v1", decoded.Version)
	}
}

func TestCacheDelete(t *testing.T) {
	dir := t.TempDir()
	cache := NewCache(dir)

	catalog := &Catalog{Version: "v1", Entries: nil}
	if err := cache.Save(catalog); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := cache.Delete(); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := os.Stat(cache.Path()); !os.IsNotExist(err) {
		t.Fatal("cache file should be deleted")
	}
}

func TestCacheDeleteMissing(t *testing.T) {
	dir := t.TempDir()
	cache := NewCache(dir)

	if err := cache.Delete(); err != nil {
		t.Fatalf("Delete non-existing: %v", err)
	}
}

func TestCachePath(t *testing.T) {
	dir := t.TempDir()
	cache := NewCache(dir)
	expected := filepath.Join(dir, "catalog.json")
	if cache.Path() != expected {
		t.Fatalf("path = %q, want %q", cache.Path(), expected)
	}
}

func TestNewHTTPClientRequiresDeviceMTLSCredentials(t *testing.T) {
	_, err := NewHTTPClient(HTTPClientConfig{CloudURL: "https://cloud.example"})
	if err == nil {
		t.Fatalf("NewHTTPClient accepted missing mTLS credentials")
	}
	if !strings.Contains(err.Error(), "mTLS") {
		t.Fatalf("error = %q, want mTLS requirement", err.Error())
	}
}

// --- Syncer tests ---

type fakeSyncClient struct {
	catalog *Catalog
	err     error
	calls   int
}

func (f *fakeSyncClient) FetchCatalog(_ context.Context, currentVersion string) (*Catalog, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	if f.catalog != nil && f.catalog.Version == currentVersion {
		return nil, nil // 304
	}
	return f.catalog, nil
}

func TestSyncerSyncsAndCaches(t *testing.T) {
	dir := t.TempDir()
	cache := NewCache(dir)

	serverCatalog := &Catalog{
		Version: "v2-xyz",
		Entries: []CatalogEntry{
			{FQDN: "app.internal", Port: 443, Protocol: "https", ResourceID: "r1"},
		},
		UpdatedAt: time.Now().UTC(),
	}

	var lastMeta CatalogMeta
	client := &fakeSyncClient{catalog: serverCatalog}

	syncer := NewSyncer(SyncerConfig{
		Client:   client,
		Cache:    cache,
		Interval: time.Hour,
		OnUpdate: func(meta CatalogMeta) { lastMeta = meta },
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		syncer.Run(ctx)
		close(done)
	}()

	// Wait for initial sync.
	deadline := time.After(2 * time.Second)
	for {
		if syncer.Version() == "v2-xyz" {
			break
		}
		select {
		case <-deadline:
			t.Fatal("syncer did not pick up catalog")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	cancel()
	<-done

	if syncer.EntryCount() != 1 {
		t.Fatalf("entry count = %d, want 1", syncer.EntryCount())
	}

	entry, ok := syncer.Lookup("app.internal")
	if !ok {
		t.Fatal("Lookup failed for app.internal")
	}
	if entry.Port != 443 {
		t.Fatalf("port = %d, want 443", entry.Port)
	}

	if lastMeta.Version != "v2-xyz" {
		t.Fatalf("callback version = %q, want v2-xyz", lastMeta.Version)
	}
	if lastMeta.EntryCount != 1 {
		t.Fatalf("callback entry count = %d, want 1", lastMeta.EntryCount)
	}

	// Verify cache was written.
	cached, err := cache.Load()
	if err != nil {
		t.Fatalf("cache load: %v", err)
	}
	if cached == nil || cached.Version != "v2-xyz" {
		t.Fatalf("cached version = %v", cached)
	}
}

func TestSyncerLoadsFromCacheOnStartup(t *testing.T) {
	dir := t.TempDir()
	cache := NewCache(dir)

	existing := &Catalog{
		Version:   "v1-cached",
		Entries:   []CatalogEntry{{FQDN: "cached.test", Port: 80}},
		UpdatedAt: time.Now().UTC(),
	}
	if err := cache.Save(existing); err != nil {
		t.Fatalf("save: %v", err)
	}

	syncer := NewSyncer(SyncerConfig{
		Client:   &fakeSyncClient{}, // server returns nil (no catalog)
		Cache:    cache,
		Interval: time.Hour,
	})

	if syncer.Version() != "v1-cached" {
		t.Fatalf("version = %q, want v1-cached", syncer.Version())
	}
	if _, ok := syncer.Lookup("cached.test"); !ok {
		t.Fatal("expected cached entry to be available before sync")
	}
}

func TestSyncerSkipsWhenVersionUnchanged(t *testing.T) {
	serverCatalog := &Catalog{
		Version:   "v3",
		Entries:   []CatalogEntry{{FQDN: "x.test", Port: 80}},
		UpdatedAt: time.Now().UTC(),
	}
	client := &fakeSyncClient{catalog: serverCatalog}

	updateCount := 0
	syncer := NewSyncer(SyncerConfig{
		Client:   client,
		Interval: time.Hour,
		OnUpdate: func(_ CatalogMeta) { updateCount++ },
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { syncer.Run(ctx); close(done) }()

	// Wait for initial sync.
	deadline := time.After(2 * time.Second)
	for syncer.Version() != "v3" {
		select {
		case <-deadline:
			t.Fatal("timeout")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	cancel()
	<-done

	if updateCount != 1 {
		t.Fatalf("update count = %d, want 1 (no duplicate for same version)", updateCount)
	}
	if client.calls != 1 {
		t.Fatalf("fetch calls = %d, want 1", client.calls)
	}
}

func TestSyncerAllEntriesReturnsCopy(t *testing.T) {
	syncer := NewSyncer(SyncerConfig{Interval: time.Hour})
	syncer.catalog = &Catalog{
		Version: "v1",
		Entries: []CatalogEntry{{FQDN: "a.test", Port: 80}},
	}

	entries := syncer.AllEntries()
	if len(entries) != 1 {
		t.Fatalf("entries = %d", len(entries))
	}

	// Mutating the returned slice should not affect the syncer.
	entries[0].FQDN = "modified"
	original := syncer.AllEntries()
	if original[0].FQDN != "a.test" {
		t.Fatal("AllEntries returned a reference, not a copy")
	}
}

func TestSyncerMetaExcludesFQDNs(t *testing.T) {
	syncer := NewSyncer(SyncerConfig{Interval: time.Hour})
	syncer.catalog = &Catalog{
		Version: "v5",
		Entries: []CatalogEntry{
			{FQDN: "secret1.internal", Port: 443},
			{FQDN: "secret2.internal", Port: 443},
		},
		UpdatedAt: time.Now().UTC(),
	}

	meta := syncer.Meta()
	if meta.Version != "v5" {
		t.Fatalf("version = %q", meta.Version)
	}
	if meta.EntryCount != 2 {
		t.Fatalf("entry count = %d", meta.EntryCount)
	}

	// Verify Meta struct doesn't contain FQDN fields.
	metaJSON, _ := json.Marshal(meta)
	metaStr := string(metaJSON)
	if contains(metaStr, "secret1") || contains(metaStr, "secret2") || contains(metaStr, "fqdn") {
		t.Fatalf("CatalogMeta JSON leaks FQDN data: %s", metaStr)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
