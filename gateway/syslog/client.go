package syslog

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"gateway/internal/models"
)

// Client sends structured log entries to the syslog aggregator over TCP.
// When the connection is down, entries are buffered in a ring buffer and
// flushed on successful reconnection to prevent audit log loss.
type Client struct {
	addr      string
	service   string
	mu        sync.Mutex
	conn      net.Conn
	tlsConfig *tls.Config
	authToken string

	// Ring buffer for entries that could not be sent
	ringBuf     [][]byte
	ringBufSize int // max capacity
}

// NewClient creates a new syslog client
func NewClient(syslogAddr, serviceName string, tlsConfig *tls.Config, authToken string) *Client {
	return &Client{
		addr:        syslogAddr,
		service:     serviceName,
		tlsConfig:   tlsConfig,
		authToken:   authToken,
		ringBufSize: 1000,
	}
}

// dial creates a TCP or TLS connection depending on configuration
func (c *Client) dial() (net.Conn, error) {
	if c.tlsConfig != nil {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		return tls.DialWithDialer(dialer, "tcp", c.addr, c.tlsConfig)
	}
	return net.DialTimeout("tcp", c.addr, 5*time.Second)
}

// sendAuthFrame sends the auth token frame after connecting
func (c *Client) sendAuthFrame(conn net.Conn) error {
	if c.authToken == "" {
		return nil
	}
	frame, _ := json.Marshal(struct {
		AuthToken string `json:"auth_token"`
	}{AuthToken: c.authToken})
	frame = append(frame, '\n')
	_, err := conn.Write(frame)
	return err
}

// connect establishes or re-establishes the TCP/TLS connection
func (c *Client) connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		c.conn.Close()
	}

	conn, err := c.dial()
	if err != nil {
		return fmt.Errorf("syslog connect: %w", err)
	}
	if err := c.sendAuthFrame(conn); err != nil {
		conn.Close()
		return fmt.Errorf("syslog auth: %w", err)
	}
	c.conn = conn
	return nil
}

// Send sends a single log entry to the syslog server.
// On failure after reconnect, the entry is buffered in a ring buffer.
func (c *Client) Send(entry *models.LogEntry) error {
	entry.Service = c.service
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	c.mu.Lock()
	defer c.mu.Unlock()

	// Lazy connect
	if c.conn == nil {
		conn, err := c.dial()
		if err != nil {
			c.bufferLocked(data)
			return fmt.Errorf("syslog unavailable: %w", err)
		}
		if err := c.sendAuthFrame(conn); err != nil {
			conn.Close()
			c.bufferLocked(data)
			return fmt.Errorf("syslog auth: %w", err)
		}
		c.conn = conn
		c.flushBufferLocked()
	}

	_, err = c.conn.Write(data)
	if err != nil {
		// Try reconnecting once
		c.conn.Close()
		conn, err2 := c.dial()
		if err2 != nil {
			c.conn = nil
			c.bufferLocked(data)
			return fmt.Errorf("syslog unavailable: %w", err2)
		}
		if err3 := c.sendAuthFrame(conn); err3 != nil {
			conn.Close()
			c.conn = nil
			c.bufferLocked(data)
			return fmt.Errorf("syslog auth: %w", err3)
		}
		c.conn = conn
		c.flushBufferLocked()
		_, err = c.conn.Write(data)
		if err != nil {
			c.bufferLocked(data)
		}
	}
	return err
}

// bufferLocked appends data to the ring buffer (caller must hold c.mu).
func (c *Client) bufferLocked(data []byte) {
	if c.ringBufSize <= 0 {
		return
	}
	if len(c.ringBuf) >= c.ringBufSize {
		// Drop oldest entry
		c.ringBuf = c.ringBuf[1:]
	}
	entry := make([]byte, len(data))
	copy(entry, data)
	c.ringBuf = append(c.ringBuf, entry)
}

// flushBufferLocked sends all buffered entries (caller must hold c.mu and have a valid c.conn).
func (c *Client) flushBufferLocked() {
	if len(c.ringBuf) == 0 || c.conn == nil {
		return
	}
	flushed := 0
	for _, data := range c.ringBuf {
		if _, err := c.conn.Write(data); err != nil {
			log.Printf("[SYSLOG] Failed to flush %d/%d buffered entries", flushed, len(c.ringBuf))
			c.ringBuf = c.ringBuf[flushed:]
			return
		}
		flushed++
	}
	if flushed > 0 {
		log.Printf("[SYSLOG] Flushed %d buffered entries on reconnect", flushed)
	}
	c.ringBuf = nil
}

// Info sends an info-level log entry (non-blocking)
func (c *Client) Info(event, message string, fields map[string]string) {
	go func() {
		if err := c.Send(&models.LogEntry{
			Level:   "info",
			Event:   event,
			Message: message,
			Fields:  fields,
		}); err != nil {
			log.Printf("[LOG] Failed to send to syslog: %v", err)
		}
	}()
}

// Warn sends a warning-level log entry (non-blocking)
func (c *Client) Warn(event, message string, fields map[string]string) {
	go func() {
		if err := c.Send(&models.LogEntry{
			Level:   "warn",
			Event:   event,
			Message: message,
			Fields:  fields,
		}); err != nil {
			log.Printf("[LOG] Failed to send to syslog: %v", err)
		}
	}()
}

// Error sends an error-level log entry (non-blocking)
func (c *Client) Error(event, message string, fields map[string]string) {
	go func() {
		if err := c.Send(&models.LogEntry{
			Level:   "error",
			Event:   event,
			Message: message,
			Fields:  fields,
		}); err != nil {
			log.Printf("[LOG] Failed to send to syslog: %v", err)
		}
	}()
}

// Close closes the syslog connection
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}
