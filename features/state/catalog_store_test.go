package state_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"licenta/features/catalog"
	servicestate "licenta/features/state"
)

func TestCatalogCacheStoreRoundTrip(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	path := filepath.Join(t.TempDir(), "state", "agent-catalog-cache.json")
	store := servicestate.NewCatalogCacheFileStore(path, func() time.Time { return now })
	cache := servicestate.CatalogCache{
		Version:        servicestate.CatalogCacheFileVersion,
		DeviceID:       "device-1",
		CatalogVersion: "v1",
		PolicyEpoch:    "epoch-1",
		DNSSuffixes:    []string{"example.test", "internal.test"},
		Resources:      []catalog.Resource{{FQDN: "admin.example.test", ResourceID: "res-1", Protocol: "https", Port: 443}},
		PosturePolicy:  catalog.PosturePolicy{RequiredChecks: []string{"Firewall"}, RequiredCheckStatus: "good"},
		TTLSeconds:     300,
		FetchedAt:      now.Add(-time.Minute),
		ExpiresAt:      now.Add(time.Hour),
	}

	if err := store.Save(context.Background(), cache); err != nil {
		t.Fatalf("Save catalog cache returned error: %v", err)
	}
	loaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load catalog cache returned error: %v", err)
	}
	if loaded.DeviceID != "device-1" || loaded.CatalogVersion != "v1" || loaded.PolicyEpoch != "epoch-1" || len(loaded.DNSSuffixes) != 2 || loaded.DNSSuffixes[0] != "example.test" || loaded.DNSSuffixes[1] != "internal.test" || len(loaded.Resources) != 1 || loaded.Resources[0].FQDN != "admin.example.test" || len(loaded.PosturePolicy.RequiredChecks) != 1 || loaded.PosturePolicy.RequiredChecks[0] != "Firewall" || loaded.PosturePolicy.RequiredCheckStatus != "good" || !loaded.UpdatedAt.Equal(now) {
		t.Fatalf("loaded catalog cache = %+v", loaded)
	}
}
