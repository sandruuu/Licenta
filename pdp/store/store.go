package store

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"pdp/models"

	_ "modernc.org/sqlite"
)

// Store provides thread-safe data storage backed by SQLite.
// Replaces the previous in-memory maps + JSON file persistence.
type Store struct {
	db           *sql.DB
	dataDir      string
	databasePath string

	// auditMu serialises audit_log inserts so the hash chain (S4.2) is
	// well-defined under concurrent callers. The chain is computed in
	// Go rather than in SQL so we don't depend on SQLite-specific
	// triggers/extensions.
	auditMu sync.Mutex

	// PendingAuth is ephemeral (browser auth sessions, 5-min TTL) — kept in memory
	pendingMu   sync.RWMutex
	PendingAuth map[string]*models.PendingAuthSession

	// PendingEnroll is ephemeral (browser enrollment sessions, 5-min TTL) — kept in memory
	enrollMu      sync.RWMutex
	PendingEnroll map[string]*models.PendingEnrollSession
}

// New creates a new Store with the specified data directory.
func New(dataDir string) *Store {
	s := &Store{
		dataDir:       dataDir,
		PendingAuth:   make(map[string]*models.PendingAuthSession),
		PendingEnroll: make(map[string]*models.PendingEnrollSession),
	}
	if dataDir != "" {
		os.MkdirAll(dataDir, 0755)
	}
	return s
}

// NewWithDatabasePath creates a Store with an explicit SQLite file path.
func NewWithDatabasePath(dataDir, databasePath string) *Store {
	s := New(dataDir)
	s.databasePath = databasePath
	return s
}

// InitDB opens the SQLite database and creates tables.
func (s *Store) InitDB() error {
	dbPath := s.databasePath
	if dbPath == "" && s.dataDir != "" {
		dbPath = filepath.Join(s.dataDir, "ztna.db")
	}
	if dbPath == "" {
		dbPath = "ztna.db"
	}

	var err error
	s.db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}

	// SQLite performance tuning
	s.db.Exec("PRAGMA journal_mode=WAL")
	s.db.Exec("PRAGMA synchronous=NORMAL")
	s.db.Exec("PRAGMA cache_size=5000")
	s.db.Exec("PRAGMA busy_timeout=5000")
	s.db.SetMaxOpenConns(1)

	if err := s.createTables(); err != nil {
		return fmt.Errorf("create tables: %w", err)
	}

	log.Printf("[STORE] SQLite database initialized: %s", dbPath)
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
