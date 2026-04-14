package policy

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"sync"
	"time"

	"cloud/store"
)

// GeoLocation holds the result of an IP geolocation lookup.
type GeoLocation struct {
	Latitude  float64
	Longitude float64
	City      string
	Country   string
}

// geoCache is a single cached geolocation entry with TTL.
type geoCache struct {
	loc       GeoLocation
	expiresAt time.Time
}

// GeoLocator resolves IP addresses to geographical coordinates using the
// ipapi.co free tier (HTTPS, 1000 req/day). Results are cached in-memory
// with a 1-hour TTL. All failures are graceful — callers get a zero-value
// GeoLocation and a nil error so that geolocation never blocks access.
type GeoLocator struct {
	store      *store.Store
	cache      map[string]geoCache
	mu         sync.RWMutex
	httpClient *http.Client
}

// NewGeoLocator creates a GeoLocator backed by the given store.
func NewGeoLocator(s *store.Store) *GeoLocator {
	return &GeoLocator{
		store: s,
		cache: make(map[string]geoCache),
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
		},
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

	// Check cache
	g.mu.RLock()
	if entry, ok := g.cache[ip]; ok && time.Now().Before(entry.expiresAt) {
		g.mu.RUnlock()
		return entry.loc, nil
	}
	g.mu.RUnlock()

	// Call ipapi.co (free tier, HTTPS, 1000 req/day)
	url := fmt.Sprintf("https://ipapi.co/%s/json/", ip)
	resp, err := g.httpClient.Get(url)
	if err != nil {
		log.Printf("[GEO] ipapi.co request failed for %s: %v", ip, err)
		return GeoLocation{}, nil // graceful fallback
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		log.Printf("[GEO] ipapi.co rate limited for %s", ip)
		return GeoLocation{}, nil
	}

	var result struct {
		Error       bool    `json:"error"`
		Reason      string  `json:"reason"`
		Latitude    float64 `json:"latitude"`
		Longitude   float64 `json:"longitude"`
		City        string  `json:"city"`
		CountryName string  `json:"country_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("[GEO] ipapi.co decode failed for %s: %v", ip, err)
		return GeoLocation{}, nil
	}

	if result.Error {
		log.Printf("[GEO] ipapi.co lookup failed for %s: %s", ip, result.Reason)
		return GeoLocation{}, nil
	}

	loc := GeoLocation{
		Latitude:  result.Latitude,
		Longitude: result.Longitude,
		City:      result.City,
		Country:   result.CountryName,
	}

	// Cache for 1 hour
	g.mu.Lock()
	g.cache[ip] = geoCache{loc: loc, expiresAt: time.Now().Add(1 * time.Hour)}
	// Evict expired entries when cache grows large
	if len(g.cache) > 10000 {
		now := time.Now()
		for k, v := range g.cache {
			if now.After(v.expiresAt) {
				delete(g.cache, k)
			}
		}
	}
	g.mu.Unlock()

	return loc, nil
}

// GeoVelocityResult holds the result of an impossible-travel check.
type GeoVelocityResult struct {
	IsImpossible bool
	IsSuspicious bool
	SpeedKmH     float64 // estimated travel speed in km/h
	DistanceKm   float64 // great-circle distance in km
	TimeDeltaH   float64 // time between events in hours
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
	if dist < 50 {
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
	case speed > 900:
		result.IsImpossible = true
		result.IsSuspicious = true
		log.Printf("[GEO] IMPOSSIBLE TRAVEL: user=%s speed=%.0f km/h dist=%.0f km time=%.2f h (%s → %s)",
			userID, speed, dist, timeDelta, prev.City, currentLoc.City)
	case speed > 500:
		result.IsSuspicious = true
		log.Printf("[GEO] SUSPICIOUS TRAVEL: user=%s speed=%.0f km/h dist=%.0f km time=%.2f h (%s → %s)",
			userID, speed, dist, timeDelta, prev.City, currentLoc.City)
	}

	return result
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
