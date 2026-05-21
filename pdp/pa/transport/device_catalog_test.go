package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"pdp/models"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestDeviceCatalogGRPCInterceptorRequiresEnrolledMTLSIdentity(t *testing.T) {
	server, dataStore := newDeviceAPITestServer(t)
	certPEM, cert := newDeviceAPICertificate(t, "device-1", time.Now().Add(time.Hour))
	accessToken := newDeviceCatalogAccessToken(t, server, dataStore, "device-1", "admin", clientCertificateFingerprint(cert))
	dataStore.SaveDeviceEnrollment(&models.DeviceEnrollment{
		ID:              "enroll-1",
		DeviceID:        "device-1",
		Component:       "endpoint",
		Status:          "approved",
		CertPEM:         string(certPEM),
		CertFingerprint: clientCertificateFingerprint(cert),
		EnrolledAt:      time.Now().Add(-time.Minute),
		ExpiresAt:       time.Now().Add(time.Hour),
	})
	dataStore.SaveResource(&models.Resource{
		ID:           "res-1",
		TenantID:     transportTestTenantID,
		GatewayID:    "gw-1",
		Name:         "Admin Portal",
		Type:         "web",
		ExternalURL:  "https://admin.example.test/app",
		Port:         443,
		Enabled:      true,
		AllowedRoles: []string{"admin"},
		Metadata:     map[string]string{"dns_suffix": "example.test"},
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	})
	dataStore.SavePolicyRule(&models.PolicyRule{
		ID:       "policy-posture-1",
		Name:     "Require managed endpoint posture",
		Priority: 1,
		Enabled:  true,
		Conditions: models.RuleConditions{
			AllowedRoles:        []string{"admin"},
			RequiredChecks:      []string{"Firewall", "Disk Encryption"},
			RequiredCheckStatus: "good",
		},
		Action:    "allow",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	dataStore.SavePolicyAssignment(&models.PolicyAssignment{
		ID:        "assignment-posture-1",
		PolicyID:  "policy-posture-1",
		TenantID:  transportTestTenantID,
		Level:     "organization",
		Priority:  1,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	service := &deviceCatalogGRPCService{server: server}
	request, err := structpb.NewStruct(map[string]interface{}{"access_token": accessToken})
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	grpcContext := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}}})

	response, err := server.deviceCatalogGRPCAuthInterceptor()(grpcContext, request, &grpc.UnaryServerInfo{FullMethod: deviceCatalogGRPCGetCatalogPath}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return service.GetCatalog(ctx, req.(*structpb.Struct))
	})
	if err != nil {
		t.Fatalf("gRPC catalog call failed: %v", err)
	}

	responseStruct, ok := response.(*structpb.Struct)
	if !ok {
		t.Fatalf("response type = %T, want *structpb.Struct", response)
	}
	fields := responseStruct.GetFields()
	if fields["version"] == nil || fields["version"].GetStringValue() == "" {
		t.Fatalf("missing catalog version in response: %+v", fields)
	}
	for _, forbidden := range []string{"fqdn", "resource_id", "protocol", "port"} {
		if _, ok := fields[forbidden]; ok {
			t.Fatalf("catalog response leaked top-level %s: %+v", forbidden, fields)
		}
	}
	suffixes := fields["dns_suffixes"].GetListValue().GetValues()
	if len(suffixes) != 1 || suffixes[0].GetStringValue() != "example.test" {
		t.Fatalf("dns_suffixes = %+v", fields["dns_suffixes"])
	}
	resources := fields["resources"].GetListValue().GetValues()
	if len(resources) != 1 {
		t.Fatalf("resources = %+v", fields["resources"])
	}
	resource := resources[0].GetStructValue().GetFields()
	if resource["fqdn"].GetStringValue() != "admin.example.test" || resource["resource_id"].GetStringValue() != "res-1" || resource["protocol"].GetStringValue() != "https" || int(resource["port"].GetNumberValue()) != 443 {
		t.Fatalf("resource = %+v", resource)
	}
	posturePolicy := fields["posture_policy"].GetStructValue()
	if posturePolicy == nil {
		t.Fatalf("missing posture policy: %+v", fields)
	}
	postureFields := posturePolicy.GetFields()
	checks := postureFields["required_checks"].GetListValue().GetValues()
	if len(checks) != 2 || checks[0].GetStringValue() != "Disk Encryption" || checks[1].GetStringValue() != "Firewall" || postureFields["required_check_status"].GetStringValue() != "good" {
		t.Fatalf("posture policy = %+v", posturePolicy.AsMap())
	}
}

func TestDeviceCatalogGRPCInterceptorRejectsFingerprintMismatch(t *testing.T) {
	server, dataStore := newDeviceAPITestServer(t)
	_, cert := newDeviceAPICertificate(t, "device-1", time.Now().Add(time.Hour))
	dataStore.SaveDeviceEnrollment(&models.DeviceEnrollment{
		ID:              "enroll-1",
		DeviceID:        "device-1",
		Component:       "endpoint",
		Status:          "approved",
		CertFingerprint: strings.Repeat("0", 64),
		EnrolledAt:      time.Now().Add(-time.Minute),
		ExpiresAt:       time.Now().Add(time.Hour),
	})

	request, err := structpb.NewStruct(map[string]interface{}{})
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	grpcContext := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}}})

	_, err = server.deviceCatalogGRPCAuthInterceptor()(grpcContext, request, &grpc.UnaryServerInfo{FullMethod: deviceCatalogGRPCGetCatalogPath}, func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatalf("gRPC handler should not be reached")
		return nil, nil
	})
	if err == nil {
		t.Fatalf("expected gRPC auth error")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status code = %s, want %s", status.Code(err), codes.PermissionDenied)
	}
}
