package store

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
)

// Store provides thread-safe data storage backed by PostgreSQL.
type Store struct {
	db          *DB
	dataDir     string
	databaseURL string

	// auditMu serializes audit_log inserts so the hash chain is deterministic
	// under concurrent callers.
	auditMu sync.Mutex
}

// New creates a Store using PDP_DATABASE_URL.
func New(dataDir string) *Store {
	return NewWithDatabaseURL(dataDir, os.Getenv(databaseURLEnv))
}

// NewWithDatabaseURL creates a Store with the PostgreSQL connection string.
func NewWithDatabaseURL(dataDir, databaseURL string) *Store {
	s := &Store{
		dataDir:     dataDir,
		databaseURL: strings.TrimSpace(databaseURL),
	}
	if dataDir != "" {
		_ = os.MkdirAll(dataDir, 0o755)
	}
	return s
}

// InitDB opens the PostgreSQL database and creates tables.
func (s *Store) InitDB() error {
	databaseURL := strings.TrimSpace(s.databaseURL)
	if databaseURL == "" {
		return fmt.Errorf("database_url is required")
	}

	db, err := openPostgres(databaseURL)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	s.db = db
	if err := s.db.Ping(); err != nil {
		_ = s.db.Close()
		s.db = nil
		return fmt.Errorf("ping database: %w", err)
	}

	if err := s.createTables(); err != nil {
		_ = s.db.Close()
		s.db = nil
		return fmt.Errorf("create tables: %w", err)
	}
	s.EnsureDefaultGlobalPoliciesForOrganizations()

	log.Printf("[STORE] PostgreSQL database initialized")
	return nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Ping checks database connectivity.
func (s *Store) Ping() error {
	if s.db == nil {
		return fmt.Errorf("database not initialized")
	}
	return s.db.Ping()
}
