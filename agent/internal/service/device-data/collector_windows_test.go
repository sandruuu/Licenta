//go:build windows

package devicedata

import (
	"strings"
	"testing"
	"time"
)

func TestAntivirusCheckFromSecurityCenterBitdefender(t *testing.T) {
	check := antivirusCheckFromInfo(map[string]any{
		"Provider":              "Windows Security Center",
		"ProductName":           "Bitdefender Endpoint Security Tools",
		"ProductState":          "397568",
		"ProductStateHex":       "061100",
		"SecurityCenterEnabled": true,
		"SecurityCenterState":   "On",
		"SignaturesUpToDate":    true,
		"SignatureState":        "UpToDate",
	}, nil)

	if check.Status != StatusGood {
		t.Fatalf("Status = %q, want %q: %+v", check.Status, StatusGood, check)
	}
	if !strings.Contains(check.Description, "Bitdefender") {
		t.Fatalf("Description = %q, want Bitdefender product name", check.Description)
	}
}

func TestAntivirusCheckFromSecurityCenterDisabledProduct(t *testing.T) {
	check := antivirusCheckFromInfo(map[string]any{
		"Provider":              "Windows Security Center",
		"ProductName":           "Bitdefender Endpoint Security Tools",
		"ProductState":          "393216",
		"ProductStateHex":       "060000",
		"SecurityCenterEnabled": false,
		"SecurityCenterState":   "Off",
		"SignaturesUpToDate":    true,
		"SignatureState":        "UpToDate",
	}, nil)

	if check.Status != StatusCritical {
		t.Fatalf("Status = %q, want %q: %+v", check.Status, StatusCritical, check)
	}
}

func TestAntivirusCheckFromDefenderFallback(t *testing.T) {
	check := antivirusCheckFromInfo(map[string]any{
		"Provider":                  "Microsoft Defender",
		"ProductName":               "Microsoft Defender Antivirus",
		"AntivirusEnabled":          true,
		"RealTimeProtectionEnabled": true,
		"AMServiceEnabled":          true,
		"SignatureAge":              1,
	}, nil)

	if check.Status != StatusGood {
		t.Fatalf("Status = %q, want %q: %+v", check.Status, StatusGood, check)
	}
}

func TestStabilizeCheckKeepsRecentValidResultForTransientUnavailable(t *testing.T) {
	now := time.Date(2026, 6, 29, 10, 0, 0, 0, time.UTC)
	collector := &defaultCollector{
		cache: map[string]cachedDeviceCheck{
			"Antivirus": {
				check:       Check{Name: "Antivirus", Status: StatusGood, Description: "Bitdefender is enabled"},
				collectedAt: now.Add(-time.Minute),
			},
		},
	}

	check, fallback := collector.stabilizeCheck("Antivirus", Check{
		Name:        "Antivirus",
		Status:      StatusUnavailable,
		Description: "Antivirus status is unavailable",
		Details:     map[string]string{"Reason": "temporary WMI failure"},
	}, now)

	if !fallback {
		t.Fatal("fallback = false, want true")
	}
	if check.Status != StatusGood || !strings.Contains(check.Description, "Bitdefender") {
		t.Fatalf("check = %+v, want recent valid antivirus result", check)
	}
	if check.Details[deviceCheckWarningField] == "" {
		t.Fatalf("details = %+v, want transient collection warning", check.Details)
	}
}

func TestStabilizeCheckDoesNotHidePersistentUnavailable(t *testing.T) {
	now := time.Date(2026, 6, 29, 10, 0, 0, 0, time.UTC)
	collector := &defaultCollector{
		cache: map[string]cachedDeviceCheck{
			"Antivirus": {
				check:       Check{Name: "Antivirus", Status: StatusGood, Description: "Bitdefender is enabled"},
				collectedAt: now.Add(-(unavailableCheckGrace + time.Second)),
			},
		},
	}

	check, fallback := collector.stabilizeCheck("Antivirus", Check{
		Name:        "Antivirus",
		Status:      StatusUnavailable,
		Description: "Antivirus status is unavailable",
	}, now)

	if fallback {
		t.Fatal("fallback = true, want false after grace period")
	}
	if check.Status != StatusUnavailable {
		t.Fatalf("Status = %q, want %q", check.Status, StatusUnavailable)
	}
}
