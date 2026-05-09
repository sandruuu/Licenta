package main

import (
	"encoding/json"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// HealthAppConfig holds the device-health-app configuration
type HealthAppConfig struct {
	// CloudURL is the base URL of the ZTNA cloud API
	CloudURL string `json:"cloud_url"`

	// DeviceID uniquely identifies this device
	DeviceID string `json:"device_id"`

	// ReportIntervalSeconds is how often to send health reports to the cloud
	ReportIntervalSeconds int `json:"report_interval_seconds"`

	// LocalAPIAddr is the address for the local IPC API (connect-app uses this)
	LocalAPIAddr string `json:"local_api_addr"`

	// DataDir is where enrollment state (keys, certs) is stored
	DataDir string `json:"data_dir,omitempty"`

	// TLS settings for cloud connectivity
	ServerCAFile    string `json:"server_ca_file,omitempty"`
	ServerName      string `json:"server_name,omitempty"`
	CloudCertSHA256 string `json:"cloud_cert_sha256,omitempty"` // SHA-256 fingerprint of cloud TLS cert for pinning
}

// DefaultHealthAppConfig returns config with sensible defaults
func DefaultHealthAppConfig() *HealthAppConfig {
	return &HealthAppConfig{
		CloudURL:              "https://localhost:8443",
		ReportIntervalSeconds: 300,
		LocalAPIAddr:          "127.0.0.1:12080",
	}
}

// LoadHealthAppConfig loads config from a JSON file.
// Falls back to defaults if the file doesn't exist.
func LoadHealthAppConfig(path string) *HealthAppConfig {
	cfg := DefaultHealthAppConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("[CONFIG] Config file %s not found, using defaults", path)
		return cfg
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		log.Printf("[CONFIG] Failed to parse config file %s: %v — using defaults", path, err)
		return cfg
	}

	// Validate and enforce minimum values
	if cfg.CloudURL == "" {
		log.Printf("[CONFIG] Warning: cloud_url is empty, using default")
		cfg.CloudURL = "https://localhost:8443"
	} else {
		parsed, err := url.Parse(cfg.CloudURL)
		if err != nil || parsed.Scheme != "https" {
			log.Printf("[CONFIG] cloud_url must use https scheme, got %q — using default", cfg.CloudURL)
			cfg.CloudURL = "https://localhost:8443"
		}
	}
	if cfg.DeviceID == "" {
		log.Printf("[CONFIG] device_id not set, will be derived from key fingerprint")
	}
	if cfg.ReportIntervalSeconds < 10 {
		log.Printf("[CONFIG] Warning: report_interval_seconds too low (%d), using minimum 10s", cfg.ReportIntervalSeconds)
		cfg.ReportIntervalSeconds = 10
	}
	if cfg.LocalAPIAddr == "" {
		cfg.LocalAPIAddr = "127.0.0.1:12080"
	}

	// Sanitize DataDir: reject path traversal, absolute paths, and symlink escapes
	if cfg.DataDir != "" {
		cleaned := filepath.Clean(cfg.DataDir)
		if filepath.IsAbs(cleaned) || strings.HasPrefix(cleaned, "\\\\") || strings.Contains(cleaned, "..") {
			log.Printf("[CONFIG] data_dir contains unsafe path %q, using default ./data", cfg.DataDir)
			cfg.DataDir = "./data"
		} else {
			// Verify the resolved path doesn't escape the working directory
			wd, _ := os.Getwd()
			absPath, _ := filepath.Abs(filepath.Join(wd, cleaned))
			if !strings.HasPrefix(absPath, wd) {
				log.Printf("[CONFIG] data_dir resolves outside working directory %q, using default ./data", cfg.DataDir)
				cfg.DataDir = "./data"
			}
		}
	}

	// Sanitize ServerCAFile
	if cfg.ServerCAFile != "" {
		cleaned := filepath.Clean(cfg.ServerCAFile)
		if strings.HasPrefix(cleaned, "\\\\") || strings.Contains(cleaned, "..") {
			log.Printf("[CONFIG] server_ca_file contains unsafe path %q, rejecting", cfg.ServerCAFile)
			cfg.ServerCAFile = ""
		}
	}

	return cfg
}
