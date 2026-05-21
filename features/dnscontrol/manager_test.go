package dnscontrol

import "testing"

func TestNormalizeSuffixes(t *testing.T) {
	got := NormalizeSuffixes([]string{"Example.Test", ".apps.example.test.", "*.example.test", "bad suffix", "localhost"})
	want := []string{"apps.example.test", "example.test"}
	if len(got) != len(want) {
		t.Fatalf("NormalizeSuffixes() = %+v", got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("NormalizeSuffixes() = %+v, want %+v", got, want)
		}
	}
}

func TestRuleKey(t *testing.T) {
	if got := RuleKey("*.Apps.Example.Test"); got != "ZTNA-apps-example-test" {
		t.Fatalf("RuleKey() = %q", got)
	}
}

func TestNormalizeDNSServer(t *testing.T) {
	if got := normalizeDNSServer("127.0.0.1:5353"); got != "127.0.0.1" {
		t.Fatalf("normalizeDNSServer() = %q", got)
	}
	if got := normalizeDNSServer("not an ip"); got != "" {
		t.Fatalf("normalizeDNSServer(invalid) = %q", got)
	}
}

func TestApplyRequiresDNSServerForSuffixes(t *testing.T) {
	manager := NewManager()
	if err := manager.Apply(nil, Config{DNSSuffixes: []string{"example.test"}}); err == nil {
		t.Fatalf("Apply accepted suffixes without a DNS server")
	}
}
