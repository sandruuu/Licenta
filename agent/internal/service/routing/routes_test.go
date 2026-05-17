package routing

import "testing"

func TestRoutePartsForCGNAT(t *testing.T) {
	destination, mask, err := RouteParts(DefaultCGNATCIDR)
	if err != nil {
		t.Fatalf("RouteParts returned error: %v", err)
	}
	if destination != "100.64.0.0" || mask != "255.192.0.0" {
		t.Fatalf("destination=%q mask=%q", destination, mask)
	}
}

func TestNormalizeConfigRejectsInvalidRoutes(t *testing.T) {
	if _, err := NormalizeConfig(Config{DestinationCIDR: "not-cidr", InterfaceIP: "100.64.0.1"}); err == nil {
		t.Fatalf("NormalizeConfig accepted invalid CIDR")
	}
	if _, err := NormalizeConfig(Config{DestinationCIDR: DefaultCGNATCIDR, InterfaceIP: "not-ip"}); err == nil {
		t.Fatalf("NormalizeConfig accepted invalid interface IP")
	}
}

func TestNormalizeConfigDefaultsMetric(t *testing.T) {
	config, err := NormalizeConfig(Config{InterfaceIP: "100.64.0.1"})
	if err != nil {
		t.Fatalf("NormalizeConfig returned error: %v", err)
	}
	if config.DestinationCIDR != DefaultCGNATCIDR || config.Metric != DefaultMetric {
		t.Fatalf("config = %+v", config)
	}
}
