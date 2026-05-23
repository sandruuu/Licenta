package wfpcontrol

import "testing"

func TestEncodeApplyRequestValidatesProxyAndRules(t *testing.T) {
	payload, err := encodeApplyRequest(ApplyRequest{
		ProxyAddress: "127.0.0.1",
		ProxyPort:    18787,
		ProxyPID:     1234,
		FailClosed:   true,
		Rules: []Rule{{
			SyntheticIP: "100.64.0.2",
			Port:        443,
			Protocol:    "tcp",
		}},
	})
	if err != nil {
		t.Fatalf("encodeApplyRequest returned error: %v", err)
	}
	if len(payload) == 0 {
		t.Fatalf("encodeApplyRequest returned empty payload")
	}
}

func TestEncodeApplyRequestRejectsUnsupportedProtocol(t *testing.T) {
	_, err := encodeApplyRequest(ApplyRequest{
		ProxyAddress: "127.0.0.1",
		ProxyPort:    18787,
		ProxyPID:     1234,
		Rules:        []Rule{{SyntheticIP: "100.64.0.2", Protocol: "icmp"}},
	})
	if err == nil {
		t.Fatalf("encodeApplyRequest returned nil error for unsupported protocol")
	}
}

func TestEncodeApplyRequestRequiresProxyPID(t *testing.T) {
	_, err := encodeApplyRequest(ApplyRequest{
		ProxyAddress: "127.0.0.1",
		ProxyPort:    18787,
		Rules:        []Rule{{SyntheticIP: "100.64.0.2", Protocol: "tcp"}},
	})
	if err == nil {
		t.Fatalf("encodeApplyRequest returned nil error without proxy PID")
	}
}
