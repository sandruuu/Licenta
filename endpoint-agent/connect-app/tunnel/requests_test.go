package tunnel

import (
	"encoding/json"
	"testing"
)

func TestAuthRequiredErrorCarriesMFAStepUpACRValues(t *testing.T) {
	err := authRequiredError(ResponsePayload{
		Status:    "auth_required",
		Code:      CodeMFARequired,
		ACRValues: "urn:ztna:loa:2",
		Message:   "Multi-factor authentication required",
	})
	if err == nil {
		t.Fatal("authRequiredError() = nil, want ErrAuthRequired")
	}
	if err.Code != CodeMFARequired {
		t.Fatalf("Code = %q, want %q", err.Code, CodeMFARequired)
	}
	if err.ACRValues != "urn:ztna:loa:2" {
		t.Fatalf("ACRValues = %q", err.ACRValues)
	}
	if err.AuthURL != "" {
		t.Fatalf("AuthURL = %q, want empty because Gateway must not provide OIDC URLs", err.AuthURL)
	}
}

func TestAuthRequiredErrorDefaultsLegacyAuthRequiredCode(t *testing.T) {
	err := authRequiredError(ResponsePayload{Status: "auth_required"})
	if err == nil {
		t.Fatal("authRequiredError() = nil, want ErrAuthRequired")
	}
	if err.Code != CodeAuthRequired {
		t.Fatalf("Code = %q, want %q", err.Code, CodeAuthRequired)
	}
}

func TestAuthRequiredErrorIgnoresNonAuthResponses(t *testing.T) {
	if err := authRequiredError(ResponsePayload{Status: "connected", Code: CodeOK}); err != nil {
		t.Fatalf("authRequiredError() = %v, want nil", err)
	}
}

func TestConnectRequestCarriesProcessIdentity(t *testing.T) {
	req := RequestPayload{
		Type:       "connect",
		RemoteAddr: "100.64.0.10",
		RemotePort: 3389,
		Token:      "token",
		DeviceID:   "device-1",
		Process: &ProcessIdentity{
			PID:    1234,
			Name:   "mstsc.exe",
			Path:   `C:\Windows\System32\mstsc.exe`,
			SHA256: "abcdef",
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var got RequestPayload
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.Process == nil {
		t.Fatal("Process = nil, want process identity")
	}
	if got.Process.Name != "mstsc.exe" || got.Process.SHA256 != "abcdef" || got.Process.PID != 1234 {
		t.Fatalf("Process = %+v, want mstsc.exe/abcdef/pid 1234", got.Process)
	}
}
