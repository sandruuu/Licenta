// Package sessionstore implements a persistent session store backed by SQLite
// that exposes an HTTP/JSON API for CRUD operations on sessions.
// This replaces Redis in the Duo Network Gateway model and enables
// horizontal scaling of portal instances by centralizing session state.
package sessionstore

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"gateway/internal/models"
	"gateway/store"
)

// Store is the persistent session store server
type Store struct {
	db        *store.Store
	stopChan  chan struct{}
	authToken string // shared secret for inter-service auth
}

// New creates a new session store backed by SQLite.
// The SESSION_STORE_TOKEN environment variable MUST be set; the store
// refuses to start without inter-service authentication configured.
func New(db *store.Store) *Store {
	token := os.Getenv("SESSION_STORE_TOKEN")
	if token == "" {
		log.Printf("[STORE] WARNING: SESSION_STORE_TOKEN is not set — session store API is unauthenticated!")
		log.Printf("[STORE] Set SESSION_STORE_TOKEN to a strong random secret for production use.")
	}
	return &Store{
		db:        db,
		stopChan:  make(chan struct{}),
		authToken: token,
	}
}

// requireAuth is middleware that validates the X-Store-Token header.
// When no auth token is configured, requests are rejected (fail-closed).
func (s *Store) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.authToken == "" {
			http.Error(w, `{"error":"session store authentication not configured"}`, http.StatusServiceUnavailable)
			return
		}
		token := r.Header.Get("X-Store-Token")
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.authToken)) != 1 {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// --- HTTP Handler Registration ---

// RegisterRoutes sets up the HTTP API routes
func (s *Store) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/sessions", s.requireAuth(s.handleList))          // GET
	mux.HandleFunc("/sessions/create", s.requireAuth(s.handleCreate)) // POST
	mux.HandleFunc("/sessions/get", s.requireAuth(s.handleGet))       // POST {id}
	mux.HandleFunc("/sessions/touch", s.requireAuth(s.handleTouch))   // POST {id}
	mux.HandleFunc("/sessions/revoke", s.requireAuth(s.handleRevoke)) // POST {id}
	mux.HandleFunc("/sessions/count", s.requireAuth(s.handleCount))   // GET
	mux.HandleFunc("/health", s.handleHealth)                         // GET (no auth — used by healthcheck)
}

// --- Core Session Logic ---

func (s *Store) create(sess *models.Session) {
	sess.Active = true
	sess.LastActivity = time.Now()
	if err := s.db.CreateSession(sess); err != nil {
		log.Printf("[STORE] Error creating session %s: %v", sess.ID, err)
		return
	}
	log.Printf("[STORE] Session created: %s (user=%s)", sess.ID, sess.Username)
}

func (s *Store) get(id string) (*models.Session, bool) {
	return s.db.GetSession(id)
}

func (s *Store) listActive() []*models.Session {
	return s.db.ListActiveSessions()
}

func (s *Store) touch(id string) bool {
	return s.db.TouchSession(id)
}

func (s *Store) revoke(id string) bool {
	ok := s.db.RevokeSession(id)
	if ok {
		log.Printf("[STORE] Session revoked: %s", id)
	}
	return ok
}

func (s *Store) count() int {
	return s.db.CountSessions()
}

func (s *Store) cleanExpired() int {
	return s.db.CleanExpiredSessions()
}

// StartCleanupLoop periodically removes expired sessions
func (s *Store) StartCleanupLoop(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-s.stopChan:
				return
			case <-ticker.C:
				if n := s.cleanExpired(); n > 0 {
					log.Printf("[STORE] Cleaned %d expired sessions", n)
				}
			}
		}
	}()
}

// Stop shuts down the store's cleanup loop
func (s *Store) Stop() {
	close(s.stopChan)
}

// --- HTTP Handlers ---

func (s *Store) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
	})
}

func (s *Store) handleList(w http.ResponseWriter, r *http.Request) {
	sessions := s.listActive()
	if sessions == nil {
		sessions = []*models.Session{}
	}
	writeJSON(w, http.StatusOK, sessions)
}

func (s *Store) handleCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var sess models.Session
	if err := json.NewDecoder(r.Body).Decode(&sess); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	s.create(&sess)
	writeJSON(w, http.StatusCreated, map[string]string{
		"status":     "created",
		"session_id": sess.ID,
	})
}

func (s *Store) handleGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	sess, ok := s.get(req.ID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}

	writeJSON(w, http.StatusOK, sess)
}

func (s *Store) handleTouch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if !s.touch(req.ID) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "touched"})
}

func (s *Store) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if !s.revoke(req.ID) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Store) handleCount(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]int{"active_sessions": s.count()})
}

// --- Helpers ---

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
