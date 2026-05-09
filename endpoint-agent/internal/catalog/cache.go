package catalog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultCacheFilename = "catalog.json"
)

// Cache provides persistent local storage for the device catalog.
// The cache file is written atomically (tmpfile → rename) and lives
// in the privileged endpoint state directory, readable only by SYSTEM.
type Cache struct {
	path string
}

// NewCache creates a cache backed by a JSON file in the given directory.
func NewCache(stateDir string) *Cache {
	dir := strings.TrimSpace(stateDir)
	if dir == "" {
		dir = "."
	}
	return &Cache{path: filepath.Join(dir, defaultCacheFilename)}
}

// Path returns the absolute path to the cache file.
func (c *Cache) Path() string {
	return c.path
}

// Load reads the cached catalog from disk. Returns nil, nil if the
// cache file does not exist (first run).
func (c *Cache) Load() (*Catalog, error) {
	data, err := os.ReadFile(c.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read catalog cache %s: %w", c.path, err)
	}
	var catalog Catalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("parse catalog cache %s: %w", c.path, err)
	}
	return &catalog, nil
}

// Save writes the catalog to disk atomically.
func (c *Cache) Save(catalog *Catalog) error {
	if catalog == nil {
		return nil
	}
	data, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		return fmt.Errorf("encode catalog cache: %w", err)
	}
	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create catalog cache dir %s: %w", dir, err)
	}

	// Atomic write: write to temp file, then rename.
	tmpPath := c.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("write catalog cache tmp %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, c.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename catalog cache %s: %w", c.path, err)
	}
	return nil
}

// Delete removes the cache file.
func (c *Cache) Delete() error {
	if err := os.Remove(c.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
