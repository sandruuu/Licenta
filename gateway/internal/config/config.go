package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	FileName           = "config.json"
	EnrollmentTokenEnv = "GATEWAY_ENROLLMENT_TOKEN"

	PACAPath        = "certs/pa-ca.crt"
	GatewayCertPath = "certs/gateway.crt"
	GatewayKeyPath  = "certs/gateway.key"
	GatewayCSRPath  = "certs/gateway.csr"
)

type Config struct {
	PAURL           string              `json:"pa_url"`
	EnrollmentToken string              `json:"-"`
	ControlPlane    *ControlPlaneConfig `json:"control_plane,omitempty"`
}

type ControlPlaneConfig struct {
	GatewayID      string `json:"-"`
	OrganizationID string `json:"-"`
	FQDN           string `json:"-"`
}

func DefaultConfig() *Config {
	return &Config{ControlPlane: &ControlPlaneConfig{}}
}

func Load() (*Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(FileName)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	if err := cfg.ApplyEnvironment(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (cfg *Config) Validate() error {
	if cfg == nil {
		return fmt.Errorf("config is required")
	}
	if cfg.ControlPlane == nil {
		cfg.ControlPlane = &ControlPlaneConfig{}
	}
	var validationErrors []string
	addValidationError := func(message string) {
		validationErrors = append(validationErrors, message)
	}
	requiredString := func(field, value string) {
		if strings.TrimSpace(value) == "" {
			addValidationError(fmt.Sprintf("%s is required", field))
		}
	}

	requiredString("pa_url", cfg.PAURL)

	if len(validationErrors) > 0 {
		return fmt.Errorf("invalid config: %s", strings.Join(validationErrors, "; "))
	}
	return nil
}

func (cfg *Config) ApplyEnvironment() error {
	token := strings.TrimSpace(os.Getenv(EnrollmentTokenEnv))
	if token == "" {
		return nil
	}
	resolved, err := resolveSecretRef(token)
	if err != nil {
		return err
	}
	cfg.EnrollmentToken = resolved
	return nil
}

func AtomicWriteFile(path string, data []byte, mode os.FileMode) error {
	if path == "" {
		return fmt.Errorf("path is required")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func resolveSecretRef(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "file:") {
		return value, nil
	}
	data, err := os.ReadFile(strings.TrimPrefix(value, "file:"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
