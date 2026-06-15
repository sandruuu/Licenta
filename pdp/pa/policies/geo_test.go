package policies

import (
	"testing"
	"time"

	"pdp/internal/testdb"
	"pdp/store"
)

func TestCheckAccessLocationBuildsUserBaselineAfterEnoughHistory(t *testing.T) {
	s := newGeoTestStore(t)
	geo := NewGeoLocator(s, newGeoTestRuntime())
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
	geo := NewGeoLocator(s, newGeoTestRuntime())
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
	geo := NewGeoLocator(s, newGeoTestRuntime())
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
	geo.cacheLocation(ip, loc)
}

func newGeoTestStore(t *testing.T) *store.Store {
	t.Helper()
	return testdb.NewStore(t)
}

type geoTestRuntime struct {
	values map[string][]byte
}

func newGeoTestRuntime() *geoTestRuntime {
	return &geoTestRuntime{values: map[string][]byte{}}
}

func (r *geoTestRuntime) SaveEphemeralState(kind, key string, value []byte, _ time.Time) error {
	r.values[kind+":"+key] = append([]byte(nil), value...)
	return nil
}

func (r *geoTestRuntime) GetEphemeralState(kind, key string) ([]byte, bool) {
	value, ok := r.values[kind+":"+key]
	return append([]byte(nil), value...), ok
}

func (r *geoTestRuntime) DeleteEphemeralState(kind, key string) error {
	delete(r.values, kind+":"+key)
	return nil
}
