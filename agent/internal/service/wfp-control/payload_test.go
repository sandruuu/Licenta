package wfpcontrol

import (
	"encoding/binary"
	"testing"
)

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

func TestDecodeDestinationPayloadIncludesProcessIDWhenPresent(t *testing.T) {
	payload := make([]byte, 20)
	binary.LittleEndian.PutUint32(payload[0:4], payloadMagic)
	binary.LittleEndian.PutUint16(payload[4:6], payloadVersion)
	binary.LittleEndian.PutUint32(payload[8:12], binary.BigEndian.Uint32([]byte{100, 64, 0, 5}))
	binary.LittleEndian.PutUint16(payload[12:14], 443)
	payload[14] = protocolTCP
	binary.LittleEndian.PutUint32(payload[16:20], 4242)

	destination, err := decodeDestinationPayload(payload)
	if err != nil {
		t.Fatalf("decodeDestinationPayload returned error: %v", err)
	}
	if destination.IP != "100.64.0.5" || destination.Port != 443 || destination.Protocol != "tcp" || destination.ProcessID != 4242 {
		t.Fatalf("destination = %+v", destination)
	}
}
