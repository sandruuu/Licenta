package ipc

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNewRequestValidatesVersionAndOperation(t *testing.T) {
	request, err := NewRequest("req-1", OperationGetStatus, nil)
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	decoded, err := DecodeRequest(data)
	if err != nil {
		t.Fatalf("DecodeRequest returned error: %v", err)
	}
	if decoded.Operation != OperationGetStatus {
		t.Fatalf("operation = %q, want %q", decoded.Operation, OperationGetStatus)
	}
}

func TestDecodeRequestRejectsUnsupportedOperation(t *testing.T) {
	data := []byte(`{"version":"device-agent-ipc.v1","id":"req-1","operation":"OpenLocalhostBackdoor"}`)
	if _, err := DecodeRequest(data); err == nil {
		t.Fatalf("DecodeRequest accepted unsupported operation")
	}
}

func TestPipeSecurityDescriptorRestrictsDefaultAccess(t *testing.T) {
	descriptor, err := PipeSecurityDescriptor("")
	if err != nil {
		t.Fatalf("PipeSecurityDescriptor returned error: %v", err)
	}
	for _, required := range []string{"SY", "BA"} {
		if !strings.Contains(descriptor, required) {
			t.Fatalf("descriptor %q does not contain required SID alias %q", descriptor, required)
		}
	}
	for _, forbidden := range []string{"WD", "AN", "AU"} {
		if strings.Contains(descriptor, forbidden) {
			t.Fatalf("descriptor %q contains overly broad SID alias %q", descriptor, forbidden)
		}
	}
}

func TestPipeSecurityDescriptorAddsEnrolledUserSID(t *testing.T) {
	userSID := "S-1-5-21-1000-2000-3000-1001"
	descriptor, err := PipeSecurityDescriptor(userSID)
	if err != nil {
		t.Fatalf("PipeSecurityDescriptor returned error: %v", err)
	}
	if !strings.Contains(descriptor, userSID) {
		t.Fatalf("descriptor %q does not contain enrolled user SID", descriptor)
	}
}

func TestPipeSecurityDescriptorRejectsInvalidSID(t *testing.T) {
	if _, err := PipeSecurityDescriptor("Everyone"); err == nil {
		t.Fatalf("PipeSecurityDescriptor accepted invalid SID")
	}
}
