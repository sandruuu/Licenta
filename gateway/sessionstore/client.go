// Package sessionstore provides a client library for the session store service.
// Portal and Admin services use this client to manage sessions remotely.
package sessionstore

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"gateway/internal/models"
)

// Client communicates with the session store service via HTTP/HTTPS
type Client struct {
	baseURL   string
	http      *http.Client
	authToken string
}

// NewClient creates a new session store client
func NewClient(storeURL string, tlsConfig *tls.Config) *Client {
	transport := &http.Transport{}
	if tlsConfig != nil {
		transport.TLSClientConfig = tlsConfig
	}
	return &Client{
		baseURL: storeURL,
		http: &http.Client{
			Timeout:   5 * time.Second,
			Transport: transport,
		},
		authToken: os.Getenv("SESSION_STORE_TOKEN"),
	}
}

// doPost sends an authenticated POST request to the session store.
func (c *Client) doPost(url, contentType string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	if c.authToken != "" {
		req.Header.Set("X-Store-Token", c.authToken)
	}
	return c.http.Do(req)
}

// doGet sends an authenticated GET request to the session store.
func (c *Client) doGet(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if c.authToken != "" {
		req.Header.Set("X-Store-Token", c.authToken)
	}
	return c.http.Do(req)
}

// Create stores a new session
func (c *Client) Create(sess *models.Session) error {
	body, _ := json.Marshal(sess)
	resp, err := c.doPost(c.baseURL+"/sessions/create", "application/json", body)
	if err != nil {
		return fmt.Errorf("session store unavailable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("session store returned %d: %s", resp.StatusCode, msg)
	}
	return nil
}

// Get retrieves a session by ID
func (c *Client) Get(id string) (*models.Session, error) {
	body, _ := json.Marshal(map[string]string{"id": id})
	resp, err := c.doPost(c.baseURL+"/sessions/get", "application/json", body)
	if err != nil {
		return nil, fmt.Errorf("session store unavailable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	var sess models.Session
	if err := json.NewDecoder(resp.Body).Decode(&sess); err != nil {
		return nil, fmt.Errorf("decode session: %w", err)
	}
	return &sess, nil
}

// Touch updates the last activity time for a session
func (c *Client) Touch(id string) error {
	body, _ := json.Marshal(map[string]string{"id": id})
	resp, err := c.doPost(c.baseURL+"/sessions/touch", "application/json", body)
	if err != nil {
		return fmt.Errorf("session store unavailable: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

// Revoke deactivates a session
func (c *Client) Revoke(id string) error {
	body, _ := json.Marshal(map[string]string{"id": id})
	resp, err := c.doPost(c.baseURL+"/sessions/revoke", "application/json", body)
	if err != nil {
		return fmt.Errorf("session store unavailable: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

// ListActive returns all active sessions
func (c *Client) ListActive() ([]*models.Session, error) {
	resp, err := c.doGet(c.baseURL + "/sessions")
	if err != nil {
		return nil, fmt.Errorf("session store unavailable: %w", err)
	}
	defer resp.Body.Close()

	var sessions []*models.Session
	if err := json.NewDecoder(resp.Body).Decode(&sessions); err != nil {
		return nil, fmt.Errorf("decode sessions: %w", err)
	}
	return sessions, nil
}

// Count returns the number of active sessions
func (c *Client) Count() (int, error) {
	resp, err := c.doGet(c.baseURL + "/sessions/count")
	if err != nil {
		return 0, fmt.Errorf("session store unavailable: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]int
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("decode count: %w", err)
	}
	return result["active_sessions"], nil
}

// Health checks if the session store is healthy
func (c *Client) Health() error {
	resp, err := c.http.Get(c.baseURL + "/health")
	if err != nil {
		return fmt.Errorf("session store unavailable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("session store unhealthy: %d", resp.StatusCode)
	}
	return nil
}
