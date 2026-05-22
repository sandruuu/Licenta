package dnscontrol

import "testing"

func TestNormalizeDNSNames(t *testing.T) {
	got := NormalizeDNSNames([]string{"Example.Test", ".apps.example.test.", "*.example.test", "bad suffix", "localhost"})
	want := []string{"example.test"}
	if len(got) != len(want) {
		t.Fatalf("NormalizeDNSNames() = %+v", got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("NormalizeDNSNames() = %+v, want %+v", got, want)
		}
	}
}

func TestRuleKey(t *testing.T) {
	if got := RuleKey("app.example.test"); got != "TRUSTAGENT-app-example-test" {
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

func TestNRPTNameValueUsesExactResourceFQDN(t *testing.T) {
	if got := nrptNameValue("App.Example.Test."); got != "app.example.test" {
		t.Fatalf("nrptNameValue() = %q", got)
	}
}

func TestApplyRequiresDNSServerForDNSNames(t *testing.T) {
	manager := NewManager()
	if err := manager.Apply(nil, Config{DNSNames: []string{"example.test"}}); err == nil {
		t.Fatalf("Apply accepted DNS names without a DNS server")
	}
}
