package policies

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"pdp/config"
	"pdp/internal/testdb"
	"pdp/store"
)

func TestLocateRetriesTemporaryProviderFailures(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"latitude": 33.749,
			"longitude": -84.388,
			"city": "Atlanta",
			"country_name": "United States",
			"country_code": "US"
		}`))
	}))
	defer server.Close()

	geo := NewGeoLocator(newGeoTestStore(t), newGeoTestRuntime(), config.GeoConfig{
		ProviderURL: server.URL + "/{ip}",
		HTTPTimeout: time.Second,
		CacheTTL:    time.Minute,
	})

	loc, err := geo.Locate("185.238.28.38")
	if err != nil {
		t.Fatalf("Locate returned error: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
	if loc.City != "Atlanta" || loc.CountryCode != "US" || loc.Latitude == 0 || loc.Longitude == 0 {
		t.Fatalf("location = %+v, want Atlanta/US with coordinates", loc)
	}
}

func TestLocateUsesFallbackProviderAfterPrimaryRateLimit(t *testing.T) {
	primaryAttempts := 0
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryAttempts++
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer primary.Close()

	fallbackAttempts := 0
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackAttempts++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"success": true,
			"latitude": 33.7489954,
			"longitude": -84.3879824,
			"city": "Atlanta",
			"country": "United States",
			"country_code": "US"
		}`))
	}))
	defer fallback.Close()

	geo := NewGeoLocator(newGeoTestStore(t), newGeoTestRuntime(), config.GeoConfig{
		ProviderURL: primary.URL + "/{ip}",
		HTTPTimeout: time.Second,
		CacheTTL:    time.Minute,
	})
	geo.providerURLs = []string{primary.URL + "/{ip}", fallback.URL + "/{ip}"}

	loc, err := geo.Locate("185.238.28.51")
	if err != nil {
		t.Fatalf("Locate returned error: %v", err)
	}
	if primaryAttempts != geoLookupMaxAttempts {
		t.Fatalf("primary attempts = %d, want %d", primaryAttempts, geoLookupMaxAttempts)
	}
	if fallbackAttempts != 1 {
		t.Fatalf("fallback attempts = %d, want 1", fallbackAttempts)
	}
	if loc.City != "Atlanta" || loc.Country != "United States" || loc.CountryCode != "US" {
		t.Fatalf("fallback location = %+v, want Atlanta/United States/US", loc)
	}
}

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
