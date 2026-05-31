package flowauthorization

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
)

func TestAuthorizePayloadIncludesSessionAndProcess(t *testing.T) {
	payload, err := authorizePayload(AuthorizeRequest{
		AgentSessionToken: "agent-session-token",
		ResourceID:        "res-web",
		Protocol:          "tcp",
		Port:              443,
		Process:           &ProcessIdentity{PID: 42, Name: "browser.exe", Path: `C:\browser.exe`, SHA256: "abc", Signer: "CN=Browser"},
	})
	if err != nil {
		t.Fatalf("authorizePayload returned error: %v", err)
	}
	fields := payload.AsMap()
	if fields["access_token"] != "agent-session-token" || fields["resource_id"] != "res-web" || fields["protocol"] != "tcp" || int(fields["port"].(float64)) != 443 {
		t.Fatalf("payload = %+v", fields)
	}
	process, ok := fields["process"].(map[string]any)
	if !ok || process["name"] != "browser.exe" || int(process["pid"].(float64)) != 42 {
		t.Fatalf("process payload = %+v", fields["process"])
	}
}

func TestAuthorizeResponseFromStructParsesGatewaySession(t *testing.T) {
	expires := time.Now().UTC().Truncate(time.Second)
	payload, err := structpb.NewStruct(map[string]any{
		"decision":            "allow",
		"reason":              "matched policy",
		"risk_score":          float64(7),
		"matched_rule":        "policy-1",
		"policies":            []any{"policy-1", "policy-2"},
		"session_id":          "sess-1",
		"session_token":       "session-token",
		"gateway_id":          "gw-1",
		"gateway_endpoint":    "gateway.example.test:9443",
		"gateway_server_name": "gateway.example.test",
		"resource_id":         "res-web",
		"protocol":            "tcp",
		"port":                float64(443),
		"expires_at":          expires.Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatalf("NewStruct returned error: %v", err)
	}
	response := authorizeResponseFromStruct(payload)
	if response.Decision != "allow" || response.SessionID != "sess-1" || response.SessionToken != "session-token" || response.GatewayEndpoint != "gateway.example.test:9443" || response.GatewayServerName != "gateway.example.test" || response.Port != 443 {
		t.Fatalf("response = %+v", response)
	}
	if len(response.Policies) != 2 || response.Policies[1] != "policy-2" {
		t.Fatalf("policies = %+v", response.Policies)
	}
	if !response.ExpiresAt.Equal(expires) {
		t.Fatalf("expires = %s want %s", response.ExpiresAt, expires)
	}
}
