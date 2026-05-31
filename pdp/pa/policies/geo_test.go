package policies

import (
	"testing"
	"time"

	"pdp/store"
)

func TestCheckAccessLocationBuildsUserBaselineAfterEnoughHistory(t *testing.T) {
	s := newGeoTestStore(t)
	geo := NewGeoLocator(s)
	now := time.Now().UTC()
	userID := "user-1"

	for i := 0; i < 5; i++ {
		if err := s.SaveLoginLocationAt(userID, "198.51.100.10", 44.4268, 26.1025, "Bucharest", "Romania", now.AddDate(0, 0, -(i+1))); err != nil {
			t.Fatalf("save location: %v", err)
		}
	}
	cacheGeo(geo, "203.0.113.20", GeoLocation{
		Latitude:    51.5074,
		Longitude:   -0.1278,
		City:        "London",
		Country:     "United Kingdom",
		CountryCode: "GB",
	})

	ctx := geo.CheckAccessLocation(userID, "203.0.113.20")

	if !ctx.LocationKnown {
		t.Fatalf("LocationKnown = false, want true")
	}
	if !ctx.IsNewLocation {
		t.Fatalf("IsNewLocation = false, want true")
	}
	if !ctx.UserBaselineReady || ctx.UserBaselineEventCount != 5 || ctx.UserBaselineDistinctDays < 3 {
		t.Fatalf("Baseline = ready:%v events:%d days:%d, want ready with 5 events across >=3 days",
			ctx.UserBaselineReady, ctx.UserBaselineEventCount, ctx.UserBaselineDistinctDays)
	}
	if !ctx.UserBaselineAnomaly {
		t.Fatalf("UserBaselineAnomaly = false, want true for location outside learned baseline")
	}
}

func TestCheckAccessLocationKeepsBaselineLearningUntilThreshold(t *testing.T) {
	s := newGeoTestStore(t)
	geo := NewGeoLocator(s)
	now := time.Now().UTC()
	userID := "user-1"

	for i := 0; i < 4; i++ {
		if err := s.SaveLoginLocationAt(userID, "198.51.100.10", 44.4268, 26.1025, "Bucharest", "Romania", now.AddDate(0, 0, -(i+1))); err != nil {
			t.Fatalf("save location: %v", err)
		}
	}
	cacheGeo(geo, "203.0.113.20", GeoLocation{
		Latitude:    51.5074,
		Longitude:   -0.1278,
		City:        "London",
		Country:     "United Kingdom",
		CountryCode: "GB",
	})

	ctx := geo.CheckAccessLocation(userID, "203.0.113.20")

	if ctx.UserBaselineReady {
		t.Fatalf("UserBaselineReady = true, want false before minimum history")
	}
	if ctx.UserBaselineAnomaly {
		t.Fatalf("UserBaselineAnomaly = true, want false while baseline is learning")
	}
}

func TestCheckAccessLocationDetectsUnrealisticTravel(t *testing.T) {
	s := newGeoTestStore(t)
	geo := NewGeoLocator(s)
	userID := "user-1"
	if err := s.SaveLoginLocationAt(userID, "198.51.100.10", 40.7128, -74.0060, "New York", "United States", time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatalf("save location: %v", err)
	}
	cacheGeo(geo, "203.0.113.20", GeoLocation{
		Latitude:    51.5074,
		Longitude:   -0.1278,
		City:        "London",
		Country:     "United Kingdom",
		CountryCode: "GB",
	})

	ctx := geo.CheckAccessLocation(userID, "203.0.113.20")

	if !ctx.IsImpossible || ctx.SpeedKmH <= 900 {
		t.Fatalf("GeoVelocity = %+v, want impossible travel above threshold", ctx.GeoVelocityResult)
	}
}

func cacheGeo(geo *GeoLocator, ip string, loc GeoLocation) {
	geo.mu.Lock()
	defer geo.mu.Unlock()
	geo.cache[ip] = geoCache{loc: loc, expiresAt: time.Now().Add(time.Hour)}
}

func newGeoTestStore(t *testing.T) *store.Store {
	t.Helper()
	s := store.New(t.TempDir())
	if err := s.InitDB(); err != nil {
		t.Fatalf("InitDB() error = %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
