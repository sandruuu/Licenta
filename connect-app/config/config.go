package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	PEPAddress      string `json:"pep_address"`
	ServerName      string `json:"server_name,omitempty"`
	CertFile        string `json:"cert_file,omitempty"` // Legacy: static client cert (bypasses enrollment)
	KeyFile         string `json:"key_file,omitempty"`  // Legacy: static client key
	CAFile          string `json:"ca_file"`
	CloudURL        string `json:"cloud_url,omitempty"`         // Cloud API URL for enrollment (e.g. https://localhost:8443)
	CloudCertSHA256 string `json:"cloud_cert_sha256,omitempty"` // SHA-256 fingerprint of cloud TLS cert for pinning
	DeviceID        string `json:"device_id,omitempty"`         // Unique device identifier for enrollment
	DataDir         string `json:"data_dir,omitempty"`          // Directory for TPM key blobs and cached certs
	TUNName         string `json:"tun_name"`
	TUNIP           string `json:"tun_ip"`
	TUNNetmask      string `json:"tun_netmask"`
	CGNATRange      string `json:"cgnat_range"`
	DNSListenAddr   string `json:"dns_listen_addr"`
	UpstreamDNS     string `json:"upstream_dns"`
	InternalSuffix  string `json:"internal_suffix"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
