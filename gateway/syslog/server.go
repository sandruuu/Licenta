// Package syslog implements a centralized structured log aggregator
// that receives JSON log entries over TCP from gateway microservices.
// Logs are written to rotating files and stdout for SIEM integration.
package syslog

import (
	"bufio"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gateway/internal/models"
)

// Server is the syslog aggregation server
type Server struct {
	listenAddr string
	logDir     string
	listener   net.Listener
	mu         sync.Mutex
	logFile    *os.File
	stopChan   chan struct{}
	entries    int64

	// TLS + auth (optional, for encrypted audit channel)
	tlsCert   string
	tlsKey    string
	authToken string // if set, clients must send auth frame before logging
}

// NewServer creates a new syslog aggregator.
// If tlsCert and tlsKey are non-empty, the server listens with TLS 1.3.
// If authToken is non-empty, each client must send an auth frame as the first line.
func NewServer(listenAddr, logDir, tlsCert, tlsKey, authToken string) *Server {
	return &Server{
		listenAddr: listenAddr,
		logDir:     logDir,
		stopChan:   make(chan struct{}),
		tlsCert:    tlsCert,
		tlsKey:     tlsKey,
		authToken:  authToken,
	}
}

// Start begins listening for log entries
func (s *Server) Start() error {
	// Ensure log directory exists
	if err := os.MkdirAll(s.logDir, 0755); err != nil {
		return fmt.Errorf("create log dir: %w", err)
	}

	// Open initial log file
	if err := s.rotateLogFile(); err != nil {
		return fmt.Errorf("open log file: %w", err)
	}

	// Start TCP (or TLS) listener
	var ln net.Listener
	if s.tlsCert != "" && s.tlsKey != "" {
		cert, err := tls.LoadX509KeyPair(s.tlsCert, s.tlsKey)
		if err != nil {
			return fmt.Errorf("load syslog TLS cert: %w", err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}
		ln, err = tls.Listen("tcp", s.listenAddr, tlsConfig)
		if err != nil {
			return fmt.Errorf("tls listen: %w", err)
		}
		log.Printf("[SYSLOG] TLS enabled (cert=%s)", s.tlsCert)
	} else {
		var err error
		ln, err = net.Listen("tcp", s.listenAddr)
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}
	}
	s.listener = ln

	log.Printf("[SYSLOG] Listening on %s, writing to %s", s.listenAddr, s.logDir)

	// Start daily log rotation
	go s.rotationLoop()

	// Accept connections
	go s.acceptLoop()

	return nil
}

// Stop shuts down the syslog server
func (s *Server) Stop() {
	close(s.stopChan)
	if s.listener != nil {
		s.listener.Close()
	}
	s.mu.Lock()
	if s.logFile != nil {
		s.logFile.Close()
	}
	s.mu.Unlock()
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stopChan:
				return
			default:
				log.Printf("[SYSLOG] Accept error: %v", err)
				continue
			}
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 64*1024), 64*1024) // 64KB max line

	// Authenticate client: first line must be {"auth_token":"..."}
	if s.authToken != "" {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if !scanner.Scan() {
			log.Printf("[SYSLOG] Auth failed: no auth frame from %s", conn.RemoteAddr())
			return
		}
		var frame struct {
			AuthToken string `json:"auth_token"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &frame); err != nil ||
			subtle.ConstantTimeCompare([]byte(frame.AuthToken), []byte(s.authToken)) != 1 {
			log.Printf("[SYSLOG] Auth failed: invalid token from %s", conn.RemoteAddr())
			return
		}
		conn.SetReadDeadline(time.Time{}) // clear deadline
	}

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		// Parse the log entry for validation
		var entry models.LogEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			log.Printf("[SYSLOG] Invalid log entry: %v", err)
			continue
		}

		// Fill in timestamp if missing
		if entry.Timestamp.IsZero() {
			entry.Timestamp = time.Now()
		}

		// Write to log file
		s.writeEntry(&entry)

		// Also print to stdout for real-time monitoring
		s.printEntry(&entry)
	}
}

func (s *Server) writeEntry(entry *models.LogEntry) {
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.logFile != nil {
		s.logFile.Write(data)
		s.logFile.Write([]byte("\n"))
		s.logFile.Sync()
	}
	s.entries++
}

func (s *Server) printEntry(entry *models.LogEntry) {
	levelColor := ""
	switch entry.Level {
	case "error":
		levelColor = "\033[31m" // red
	case "warn":
		levelColor = "\033[33m" // yellow
	case "info":
		levelColor = "\033[32m" // green
	case "debug":
		levelColor = "\033[36m" // cyan
	}
	reset := "\033[0m"

	fmt.Printf("%s[%s]%s [%s] [%s] %s",
		levelColor, entry.Level, reset,
		entry.Timestamp.Format("15:04:05"),
		entry.Service,
		entry.Message,
	)

	if len(entry.Fields) > 0 {
		fields, _ := json.Marshal(entry.Fields)
		fmt.Printf(" %s", string(fields))
	}
	fmt.Println()
}

func (s *Server) rotateLogFile() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.logFile != nil {
		s.logFile.Close()
	}

	filename := fmt.Sprintf("gateway-%s.jsonl", time.Now().Format("2006-01-02"))
	path := filepath.Join(s.logDir, filename)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	s.logFile = f
	log.Printf("[SYSLOG] Log file: %s", path)
	return nil
}

func (s *Server) rotationLoop() {
	// Rotate at midnight
	for {
		now := time.Now()
		next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
		timer := time.NewTimer(next.Sub(now))

		select {
		case <-s.stopChan:
			timer.Stop()
			return
		case <-timer.C:
			if err := s.rotateLogFile(); err != nil {
				log.Printf("[SYSLOG] Rotation error: %v", err)
			}
		}
	}
}
