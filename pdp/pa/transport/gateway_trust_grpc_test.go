package transport

import (
	"testing"
	"time"

	"pdp/models"

	"google.golang.org/protobuf/types/known/structpb"
)

func TestGatewayTrustRevalidateSessionsReturnsInvalidPASessions(t *testing.T) {
	server, cert := newGatewayControlTestServer(t, "gw-1", "gateway.example.test")
	now := time.Now().UTC()
	server.pa.Store.SaveSession(&models.Session{
		ID:             "sess-valid",
		UserID:         "user-1",
		DeviceID:       "device-1",
		Resource:       "res-ssh",
		GatewayID:      "gw-1",
		Protocol:       "ssh",
		OrganizationID: transportTestOrganizationID,
		CreatedAt:      now.Add(-time.Minute),
		ExpiresAt:      now.Add(time.Hour),
	})
	server.pa.Store.SaveSession(&models.Session{
		ID:             "sess-revoked",
		UserID:         "user-1",
		DeviceID:       "device-1",
		Resource:       "res-rdp",
		GatewayID:      "gw-1",
		Protocol:       "rdp",
		OrganizationID: transportTestOrganizationID,
		CreatedAt:      now.Add(-time.Minute),
		ExpiresAt:      now.Add(time.Hour),
		Revoked:        true,
	})
	server.pa.Store.SaveSession(&models.Session{
		ID:             "sess-mismatch",
		UserID:         "user-1",
		DeviceID:       "device-1",
		Resource:       "res-web",
		GatewayID:      "gw-other",
		Protocol:       "https",
		OrganizationID: transportTestOrganizationID,
		CreatedAt:      now.Add(-time.Minute),
		ExpiresAt:      now.Add(time.Hour),
	})
	request, err := structpb.NewStruct(map[string]interface{}{
		"sessions": []interface{}{
			map[string]interface{}{"session_id": "sess-valid", "device_id": "device-1", "resource_id": "res-ssh", "protocol": "ssh"},
			map[string]interface{}{"session_id": "sess-revoked", "device_id": "device-1", "resource_id": "res-rdp", "protocol": "rdp"},
			map[string]interface{}{"session_id": "sess-missing", "device_id": "device-1", "resource_id": "res-db", "protocol": "tcp"},
			map[string]interface{}{"session_id": "sess-mismatch", "device_id": "device-1", "resource_id": "res-web", "protocol": "https"},
		},
	})
	if err != nil {
		t.Fatalf("NewStruct() error = %v", err)
	}

	response, err := (&gatewayTrustGRPCService{server: server}).RevalidateSessions(gatewayControlPeerContext(cert), request)
	if err != nil {
		t.Fatalf("RevalidateSessions() error = %v", err)
	}
	values := response.GetFields()["invalid_sessions"].GetListValue().GetValues()
	got := map[string]string{}
	for _, value := range values {
		item := value.GetStructValue()
		got[structFieldString(item, "session_id")] = structFieldString(item, "status")
	}
	want := map[string]string{
		"sess-revoked":  "revoked",
		"sess-missing":  "not_found",
		"sess-mismatch": "gateway_mismatch",
	}
	if len(got) != len(want) {
		t.Fatalf("invalid sessions = %v, want %v", got, want)
	}
	for sessionID, status := range want {
		if got[sessionID] != status {
			t.Fatalf("invalid session %s status = %q, want %q (all=%v)", sessionID, got[sessionID], status, got)
		}
	}
}
