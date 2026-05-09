package tun

import "testing"

func TestNormalizeConfigDefaults(t *testing.T) {
	config, err := NormalizeConfig(Config{})
	if err != nil {
		t.Fatalf("NormalizeConfig returned error: %v", err)
	}
	if config.Name != DefaultName || config.Address != DefaultAddress || config.Netmask != DefaultNetmask || config.DNSServer != DefaultDNSServer {
		t.Fatalf("config = %+v", config)
	}
}

func TestNormalizeConfigRejectsInvalidValues(t *testing.T) {
	if _, err := NormalizeConfig(Config{Address: "not-an-ip"}); err == nil {
		t.Fatalf("NormalizeConfig accepted invalid address")
	}
	if _, err := NormalizeConfig(Config{Netmask: "255.0.255.0"}); err == nil {
		t.Fatalf("NormalizeConfig accepted non-contiguous netmask")
	}
	if _, err := NormalizeConfig(Config{DNSServer: "127.0.0.1:53"}); err == nil {
		t.Fatalf("NormalizeConfig accepted DNS server with port")
	}
}
