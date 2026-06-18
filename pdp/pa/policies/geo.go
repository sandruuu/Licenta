package policies

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"pdp/config"
	"pdp/models"
	"pdp/store"
)

const (
	userBaselineWindow       = 30 * 24 * time.Hour
	userBaselineMaxLocations = 50
	userBaselineMinLocations = 5
	userBaselineMinDays      = 3
	geoCacheStateKind        = "geo_cache"
)

// GeoLocation holds the result of an IP geolocation lookup.
type GeoLocation struct {
	Latitude    float64
	Longitude   float64
	City        string
	Country     string
	CountryCode string
}

// geoCache is a single cached geolocation entry with TTL.
type geoCache struct {
	Loc       GeoLocation `json:"loc"`
	ExpiresAt time.Time   `json:"expires_at"`
}

// GeoLocator resolves IP addresses to geographical coordinates using the
// ipapi.co free tier (HTTPS, 1000 req/day). Results are cached in Redis
// with a 1-hour TTL. All failures are graceful — callers get a zero-value
// GeoLocation and a nil error so that geolocation never blocks access.
type GeoLocator struct {
	store                    *store.Store
	runtime                  RuntimeStateStore
	httpClient               *http.Client
	providerURL              string
	cacheTTL                 time.Duration
	cacheMaxEntries          int
	sameAreaDistanceKM       float64
	suspiciousTravelSpeedKMH float64
	impossibleTravelSpeedKMH float64
}

type RuntimeStateStore interface {
	SaveEphemeralState(kind, key string, value []byte, expiresAt time.Time) error
	GetEphemeralState(kind, key string) ([]byte, bool)
	DeleteEphemeralState(kind, key string) error
}

// NewGeoLocator creates a GeoLocator backed by the given store.
func NewGeoLocator(s *store.Store, runtimeState RuntimeStateStore, cfgs ...config.GeoConfig) *GeoLocator {
	cfg := config.GeoConfig{
		ProviderURL:              "https://ipapi.co/{ip}/json/",
		HTTPTimeout:              3 * time.Second,
		CacheTTL:                 time.Hour,
		CacheMaxEntries:          10000,
		SameAreaDistanceKM:       50,
		SuspiciousTravelSpeedKMH: 500,
		ImpossibleTravelSpeedKMH: 900,
	}
	if len(cfgs) > 0 {
		if strings.TrimSpace(cfgs[0].ProviderURL) != "" {
			cfg.ProviderURL = cfgs[0].ProviderURL
		}
		if cfgs[0].HTTPTimeout > 0 {
			cfg.HTTPTimeout = cfgs[0].HTTPTimeout
		}
		if cfgs[0].CacheTTL > 0 {
			cfg.CacheTTL = cfgs[0].CacheTTL
		}
		if cfgs[0].CacheMaxEntries > 0 {
			cfg.CacheMaxEntries = cfgs[0].CacheMaxEntries
		}
		if cfgs[0].SameAreaDistanceKM > 0 {
			cfg.SameAreaDistanceKM = cfgs[0].SameAreaDistanceKM
		}
		if cfgs[0].SuspiciousTravelSpeedKMH > 0 {
			cfg.SuspiciousTravelSpeedKMH = cfgs[0].SuspiciousTravelSpeedKMH
		}
		if cfgs[0].ImpossibleTravelSpeedKMH > 0 {
			cfg.ImpossibleTravelSpeedKMH = cfgs[0].ImpossibleTravelSpeedKMH
		}
	}
	return &GeoLocator{
		store:   s,
		runtime: runtimeState,
		httpClient: &http.Client{
			Timeout: cfg.HTTPTimeout,
		},
		providerURL:              cfg.ProviderURL,
		cacheTTL:                 cfg.CacheTTL,
		cacheMaxEntries:          cfg.CacheMaxEntries,
		sameAreaDistanceKM:       cfg.SameAreaDistanceKM,
		suspiciousTravelSpeedKMH: cfg.SuspiciousTravelSpeedKMH,
		impossibleTravelSpeedKMH: cfg.ImpossibleTravelSpeedKMH,
	}
}

// Locate resolves an IP address to a geographic location.
// Private/loopback IPs return a zero-value GeoLocation (no error).
func (g *GeoLocator) Locate(ip string) (GeoLocation, error) {
	// Skip private / loopback IPs — they have no meaningful geo
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return GeoLocation{}, nil
	}
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() {
		return GeoLocation{}, nil
	}

	if loc, ok := g.cachedLocation(ip); ok {
		return loc, nil
	}

	resp, err := g.httpClient.Get(g.lookupURL(ip))
	if err != nil {
		log.Printf("[GEO] provider request failed for %s: %v", ip, err)
		return GeoLocation{}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		log.Printf("[GEO] provider rate limited for %s", ip)
		return GeoLocation{}, nil
	}

	var result struct {
		Error       bool    `json:"error"`
		Reason      string  `json:"reason"`
		Latitude    float64 `json:"latitude"`
		Longitude   float64 `json:"longitude"`
		City        string  `json:"city"`
		CountryName string  `json:"country_name"`
		CountryCode string  `json:"country_code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("[GEO] provider decode failed for %s: %v", ip, err)
		return GeoLocation{}, nil
	}

	if result.Error {
		log.Printf("[GEO] provider lookup failed for %s: %s", ip, result.Reason)
		return GeoLocation{}, nil
	}

	loc := GeoLocation{
		Latitude:    result.Latitude,
		Longitude:   result.Longitude,
		City:        result.City,
		Country:     result.CountryName,
		CountryCode: result.CountryCode,
	}

	g.cacheLocation(ip, loc)

	return loc, nil
}

func (g *GeoLocator) cachedLocation(ip string) (GeoLocation, bool) {
	if g == nil || g.runtime == nil {
		return GeoLocation{}, false
	}
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return GeoLocation{}, false
	}
	raw, ok := g.runtime.GetEphemeralState(geoCacheStateKind, ip)
	if !ok {
		return GeoLocation{}, false
	}
	var entry geoCache
	if err := json.Unmarshal(raw, &entry); err != nil {
		_ = g.runtime.DeleteEphemeralState(geoCacheStateKind, ip)
		return GeoLocation{}, false
	}
	if !entry.ExpiresAt.IsZero() && time.Now().UTC().After(entry.ExpiresAt.UTC()) {
		_ = g.runtime.DeleteEphemeralState(geoCacheStateKind, ip)
		return GeoLocation{}, false
	}
	return entry.Loc, true
}

func (g *GeoLocator) cacheLocation(ip string, loc GeoLocation) {
	if g == nil || g.runtime == nil {
		return
	}
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return
	}
	ttl := g.cacheTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	expiresAt := time.Now().UTC().Add(ttl)
	raw, err := json.Marshal(geoCache{Loc: loc, ExpiresAt: expiresAt})
	if err != nil {
		return
	}
	_ = g.runtime.SaveEphemeralState(geoCacheStateKind, ip, raw, expiresAt)
}

func (g *GeoLocator) lookupURL(ip string) string {
	provider := strings.TrimSpace(g.providerURL)
	if provider == "" {
		provider = "https://ipapi.co/{ip}/json/"
	}
	escapedIP := url.PathEscape(ip)
	if strings.Contains(provider, "{ip}") {
		return strings.ReplaceAll(provider, "{ip}", escapedIP)
	}
	return fmt.Sprintf("%s/%s/json/", strings.TrimRight(provider, "/"), escapedIP)
}

// GeoVelocityResult holds the result of an impossible-travel check.
type GeoVelocityResult struct {
	IsImpossible bool
	IsSuspicious bool
	SpeedKmH     float64 // estimated travel speed in km/h
	DistanceKm   float64 // great-circle distance in km
	TimeDeltaH   float64 // time between events in hours
}

// AccessLocationContext describes the location context observed for an access
// request.
type AccessLocationContext struct {
	IsNewLocation            bool
	LocationKnown            bool
	Country                  string
	CountryCode              string
	UserBaselineReady        bool
	UserBaselineAnomaly      bool
	UserBaselineEventCount   int
	UserBaselineDistinctDays int
	GeoVelocityResult
}

// CheckImpossibleTravel compares the given IP's location against the user's
// most recent login location. It returns an impossible-travel result.
//
// Thresholds:
//   - < 500 km/h: normal (commercial aviation)
//   - 500–900 km/h: suspicious (VPN hop / fast jet)
//   - > 900 km/h: impossible travel
//
// Edge cases handled gracefully:
//   - First login (no history) → no flag
//   - Private IP → no flag
//   - Same city (distance ≈ 0) → no flag
//   - Geolocation failure → no flag
func (g *GeoLocator) CheckImpossibleTravel(userID, sourceIP string) GeoVelocityResult {
	empty := GeoVelocityResult{}

	// Geolocate current IP
	currentLoc, _ := g.Locate(sourceIP)
	if currentLoc.Latitude == 0 && currentLoc.Longitude == 0 {
		return empty // can't geolocate → skip
	}

	// Get previous location from DB
	prev, err := g.store.GetLastLoginLocation(userID)
	if err != nil || prev == nil {
		return empty // first login or error → skip
	}

	// Calculate distance (Haversine)
	dist := haversineKm(prev.Latitude, prev.Longitude, currentLoc.Latitude, currentLoc.Longitude)
	if dist < g.sameAreaDistanceKM {
		return empty // same metro area → no flag
	}

	// Calculate time delta
	timeDelta := time.Since(prev.Timestamp).Hours()
	if timeDelta <= 0 {
		timeDelta = 0.001 // avoid divide-by-zero
	}

	speed := dist / timeDelta

	result := GeoVelocityResult{
		SpeedKmH:   speed,
		DistanceKm: dist,
		TimeDeltaH: timeDelta,
	}

	switch {
	case speed > g.impossibleTravelSpeedKMH:
		result.IsImpossible = true
		result.IsSuspicious = true
		log.Printf("[GEO] IMPOSSIBLE TRAVEL: user=%s speed=%.0f km/h dist=%.0f km time=%.2f h (%s → %s)",
			userID, speed, dist, timeDelta, prev.City, currentLoc.City)
	case speed > g.suspiciousTravelSpeedKMH:
		result.IsSuspicious = true
		log.Printf("[GEO] SUSPICIOUS TRAVEL: user=%s speed=%.0f km/h dist=%.0f km time=%.2f h (%s → %s)",
			userID, speed, dist, timeDelta, prev.City, currentLoc.City)
	}

	return result
}

// CheckAccessLocation evaluates whether the current request comes from a new
// location and whether it implies impossible travel.
func (g *GeoLocator) CheckAccessLocation(userID, sourceIP string) AccessLocationContext {
	empty := AccessLocationContext{}

	currentLoc, _ := g.Locate(sourceIP)
	if currentLoc.Latitude == 0 && currentLoc.Longitude == 0 {
		return empty
	}

	ctx := AccessLocationContext{
		LocationKnown: true,
		Country:       currentLoc.Country,
		CountryCode:   currentLoc.CountryCode,
	}

	prev, err := g.store.GetLastLoginLocation(userID)
	if err != nil || prev == nil {
		return ctx
	}

	recent, recentErr := g.store.GetRecentLoginLocations(userID, userBaselineMaxLocations)
	if recentErr == nil && len(recent) > 0 {
		ctx.IsNewLocation = true
		for _, known := range recent {
			if known == nil {
				continue
			}
			if haversineKm(known.Latitude, known.Longitude, currentLoc.Latitude, currentLoc.Longitude) < g.sameAreaDistanceKM {
				ctx.IsNewLocation = false
				break
			}
		}
		g.populateUserBaseline(&ctx, recent, currentLoc)
	}

	dist := haversineKm(prev.Latitude, prev.Longitude, currentLoc.Latitude, currentLoc.Longitude)
	if dist < g.sameAreaDistanceKM {
		return ctx
	}

	timeDelta := time.Since(prev.Timestamp).Hours()
	if timeDelta <= 0 {
		timeDelta = 0.001
	}

	speed := dist / timeDelta
	result := GeoVelocityResult{
		SpeedKmH:   speed,
		DistanceKm: dist,
		TimeDeltaH: timeDelta,
	}

	switch {
	case speed > g.impossibleTravelSpeedKMH:
		result.IsImpossible = true
		result.IsSuspicious = true
		log.Printf("[GEO] IMPOSSIBLE TRAVEL: user=%s speed=%.0f km/h dist=%.0f km time=%.2f h (%s -> %s)",
			userID, speed, dist, timeDelta, prev.City, currentLoc.City)
	case speed > g.suspiciousTravelSpeedKMH:
		result.IsSuspicious = true
		log.Printf("[GEO] SUSPICIOUS TRAVEL: user=%s speed=%.0f km/h dist=%.0f km time=%.2f h (%s -> %s)",
			userID, speed, dist, timeDelta, prev.City, currentLoc.City)
	}

	ctx.GeoVelocityResult = result
	return ctx
}

func (g *GeoLocator) populateUserBaseline(ctx *AccessLocationContext, recent []*models.LoginLocation, currentLoc GeoLocation) {
	if ctx == nil {
		return
	}
	cutoff := time.Now().UTC().Add(-userBaselineWindow)
	distinctDays := map[string]struct{}{}
	baseline := make([]*models.LoginLocation, 0, len(recent))
	for _, loc := range recent {
		if loc == nil || loc.Timestamp.IsZero() || loc.Timestamp.Before(cutoff) {
			continue
		}
		baseline = append(baseline, loc)
		distinctDays[loc.Timestamp.UTC().Format("2006-01-02")] = struct{}{}
	}

	ctx.UserBaselineEventCount = len(baseline)
	ctx.UserBaselineDistinctDays = len(distinctDays)
	ctx.UserBaselineReady = ctx.UserBaselineEventCount >= userBaselineMinLocations &&
		ctx.UserBaselineDistinctDays >= userBaselineMinDays
	if !ctx.UserBaselineReady {
		return
	}

	ctx.UserBaselineAnomaly = true
	for _, known := range baseline {
		if haversineKm(known.Latitude, known.Longitude, currentLoc.Latitude, currentLoc.Longitude) < g.sameAreaDistanceKM {
			ctx.UserBaselineAnomaly = false
			return
		}
	}
}

// SaveCurrentLocation stores the current login location for future travel checks.
func (g *GeoLocator) SaveCurrentLocation(userID, sourceIP string) {
	loc, _ := g.Locate(sourceIP)
	if loc.Latitude == 0 && loc.Longitude == 0 {
		return // can't geolocate → don't save
	}
	if err := g.store.SaveLoginLocation(userID, sourceIP, loc.Latitude, loc.Longitude, loc.City, loc.Country); err != nil {
		log.Printf("[GEO] Failed to save login location: %v", err)
	}
}

// haversineKm calculates the great-circle distance between two
// latitude/longitude points in kilometres using the Haversine formula.
func haversineKm(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadiusKm = 6371.0
	dLat := degreesToRadians(lat2 - lat1)
	dLon := degreesToRadians(lon2 - lon1)

	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(degreesToRadians(lat1))*math.Cos(degreesToRadians(lat2))*
			math.Sin(dLon/2)*math.Sin(dLon/2)

	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return earthRadiusKm * c
}

func degreesToRadians(deg float64) float64 {
	return deg * math.Pi / 180
}
