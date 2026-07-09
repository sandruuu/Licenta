package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const configFilename = "config.json"

var executablePath = os.Executable

type configFile struct {
	PDPGRPCEndpoint       string `json:"pdp_grpc_endpoint,omitempty"`
	PDPTLSServerName      string `json:"pdp_tls_server_name,omitempty"`
	PDPCAFile             string `json:"pdp_ca_file,omitempty"`
	EnrollmentStatePath   string `json:"enrollment_state_path,omitempty"`
	PipeAuthorizedUserSID string `json:"pipe_authorized_user_sid,omitempty"`
}

func loadServiceConfig(serviceConfig ServiceConfig) (ServiceConfig, error) {
	fileConfig, found, err := loadConfig()
	if err != nil || !found {
		return serviceConfig, err
	}
	return applyServiceConfig(serviceConfig, fileConfig)
}

func loadTrayConfig(trayConfig TrayConfig) (TrayConfig, error) {
	fileConfig, found, err := loadConfig()
	if err != nil || !found {
		return trayConfig, err
	}
	return applyTrayConfig(trayConfig, fileConfig)
}

func applyServiceConfig(options ServiceConfig, config configFile) (ServiceConfig, error) {
	if err := validateServiceFileConfig(config); err != nil {
		return options, err
	}
	options.PDPGRPCEndpoint = strings.TrimSpace(config.PDPGRPCEndpoint)
	options.PDPTLSServerName = strings.TrimSpace(config.PDPTLSServerName)
	options.PDPCAFile = strings.TrimSpace(config.PDPCAFile)
	options.EnrollmentStatePath = strings.TrimSpace(config.EnrollmentStatePath)
	options.PipeAuthorizedUserSID = strings.TrimSpace(config.PipeAuthorizedUserSID)
	return options, nil
}

func validateServiceFileConfig(config configFile) error {
	if _, err := requiredConfigString("pdp_grpc_endpoint", config.PDPGRPCEndpoint); err != nil {
		return err
	}
	if _, err := requiredConfigString("pdp_tls_server_name", config.PDPTLSServerName); err != nil {
		return err
	}
	caFile, err := requiredConfigString("pdp_ca_file", config.PDPCAFile)
	if err != nil {
		return err
	}
	if err := validateCertificateFile(caFile); err != nil {
		return err
	}
	return nil
}

func requiredConfigString(name, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("agent config %s is required", name)
	}
	return value, nil
}

func validateCertificateFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read agent config pdp_ca_file: %w", err)
	}
	if !bytes.Contains(data, []byte("-----BEGIN CERTIFICATE-----")) {
		return fmt.Errorf("agent config pdp_ca_file does not look like a PEM certificate: %s", path)
	}
	return nil
}

func applyTrayConfig(options TrayConfig, _ configFile) (TrayConfig, error) {
	return options, nil
}

func loadConfig() (configFile, bool, error) {
	path, err := configPath()
	if err != nil {
		return configFile{}, false, err
	}
	config, err := readFileConfig(path)
	if err == nil {
		resolveConfigFilePaths(&config, filepath.Dir(path))
		return config, true, nil
	}
	if os.IsNotExist(err) {
		return configFile{}, false, nil
	}
	return configFile{}, false, err
}

func readFileConfig(path string) (configFile, error) {
	cleanPath := filepath.Clean(strings.TrimSpace(path))
	if cleanPath == "." || cleanPath == "" {
		return configFile{}, os.ErrNotExist
	}
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return configFile{}, err
	}
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	var config configFile
	if err := json.Unmarshal(data, &config); err != nil {
		return configFile{}, fmt.Errorf("decode agent config %s: %w", cleanPath, err)
	}
	return config, nil
}

func resolveConfigFilePaths(config *configFile, baseDir string) {
	if config == nil {
		return
	}
	config.PDPCAFile = resolveReferencedConfigPath(config.PDPCAFile, baseDir)
}

func resolveReferencedConfigPath(value, baseDir string) string {
	cleanValue := strings.TrimSpace(value)
	if cleanValue == "" || filepath.IsAbs(cleanValue) {
		return cleanValue
	}
	return filepath.Join(baseDir, cleanValue)
}

func configPath() (string, error) {
	executable, err := executablePath()
	if err != nil {
		return "", fmt.Errorf("resolve agent executable path: %w", err)
	}
	executable = strings.TrimSpace(executable)
	if executable == "" {
		return "", fmt.Errorf("agent executable path is empty")
	}
	return filepath.Join(filepath.Dir(executable), configFilename), nil
}
