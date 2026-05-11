package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"pdp/config"
	"pdp/models"
	"pdp/pa"
	"pdp/store"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestDeviceAuthMiddlewareRejectsFingerprintMismatch(t *testing.T) {
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

	handler := server.requireClientCert(server.deviceAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("handler should not be reached")
	})))
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/test-device-auth", strings.NewReader(`{}`))
	request.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestDeviceTelemetryGRPCReportPostureStoresRawData(t *testing.T) {
	server, dataStore := newDeviceAPITestServer(t)
	certPEM, cert := newDeviceAPICertificate(t, "device-1", time.Now().Add(time.Hour))
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

	request, err := structpb.NewStruct(map[string]interface{}{
		"device_id":    "device-1",
		"hostname":     "host-1",
		"os":           "Windows",
		"collected_at": "2026-05-04T10:00:00Z",
		"reported_at":  "client-owned-value-is-ignored",
		"checks": []interface{}{map[string]interface{}{
			"name":        "Firewall",
			"status":      "critical",
			"description": "disabled",
		}},
	})
	if err != nil {
		t.Fatalf("NewStruct returned error: %v", err)
	}
	grpcContext := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}}})
	service := &deviceTelemetryGRPCService{server: server}
	response, err := server.deviceCatalogGRPCAuthInterceptor()(grpcContext, request, &grpc.UnaryServerInfo{FullMethod: deviceTelemetryGRPCReportPosturePath}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return service.ReportPosture(ctx, req.(*structpb.Struct))
	})
	if err != nil {
		t.Fatalf("ReportPosture returned error: %v", err)
	}
	responseStruct, ok := response.(*structpb.Struct)
	if !ok {
		t.Fatalf("response type = %T, want *structpb.Struct", response)
	}
	reportedAt, err := time.Parse(time.RFC3339Nano, responseStruct.GetFields()["reported_at"].GetStringValue())
	if err != nil || reportedAt.IsZero() {
		t.Fatalf("reported_at response = %q, err=%v", responseStruct.GetFields()["reported_at"].GetStringValue(), err)
	}

	report, ok := dataStore.GetDevicePosture("device-1")
	if !ok {
		t.Fatalf("posture report was not stored")
	}
	if report.Hostname != "host-1" || report.OS != "Windows" || len(report.Checks) != 1 || report.Checks[0].Status != "critical" {
		t.Fatalf("report = %+v", report)
	}
	if !report.ReportedAt.Equal(reportedAt) || report.CollectedAt.IsZero() {
		t.Fatalf("timestamps = collected_at=%s reported_at=%s response=%s", report.CollectedAt, report.ReportedAt, reportedAt)
	}
}

func TestDeviceTelemetryGRPCReportPostureRejectsLocalScore(t *testing.T) {
	server, dataStore := newDeviceAPITestServer(t)
	certPEM, cert := newDeviceAPICertificate(t, "device-1", time.Now().Add(time.Hour))
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

	request, err := structpb.NewStruct(map[string]interface{}{
		"device_id":     "device-1",
		"overall_score": float64(90),
		"checks":        []interface{}{},
	})
	if err != nil {
		t.Fatalf("NewStruct returned error: %v", err)
	}
	grpcContext := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}}})
	service := &deviceTelemetryGRPCService{server: server}
	_, err = server.deviceCatalogGRPCAuthInterceptor()(grpcContext, request, &grpc.UnaryServerInfo{FullMethod: deviceTelemetryGRPCReportPosturePath}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return service.ReportPosture(ctx, req.(*structpb.Struct))
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("status code = %s, want %s (err=%v)", status.Code(err), codes.InvalidArgument, err)
	}
	if _, ok := dataStore.GetDevicePosture("device-1"); ok {
		t.Fatalf("scored posture report should not be stored")
	}
}

func TestDeviceTelemetryGRPCReportPostureRejectsDeviceMismatch(t *testing.T) {
	server, dataStore := newDeviceAPITestServer(t)
	certPEM, cert := newDeviceAPICertificate(t, "device-1", time.Now().Add(time.Hour))
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

	request, err := structpb.NewStruct(map[string]interface{}{
		"device_id": "device-2",
		"checks":    []interface{}{},
	})
	if err != nil {
		t.Fatalf("NewStruct returned error: %v", err)
	}
	grpcContext := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}}})
	service := &deviceTelemetryGRPCService{server: server}
	_, err = server.deviceCatalogGRPCAuthInterceptor()(grpcContext, request, &grpc.UnaryServerInfo{FullMethod: deviceTelemetryGRPCReportPosturePath}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return service.ReportPosture(ctx, req.(*structpb.Struct))
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status code = %s, want %s (err=%v)", status.Code(err), codes.PermissionDenied, err)
	}
	if _, ok := dataStore.GetDevicePosture("device-2"); ok {
		t.Fatalf("mismatched posture report should not be stored")
	}
}

func TestDeviceTelemetryGRPCHeartbeatTouchesPosture(t *testing.T) {
	server, dataStore := newDeviceAPITestServer(t)
	certPEM, cert := newDeviceAPICertificate(t, "device-1", time.Now().Add(time.Hour))
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
	dataStore.SaveDevicePosture(&models.DevicePostureReport{DeviceID: "device-1", ReportedAt: time.Unix(1000, 0).UTC()})

	request, err := structpb.NewStruct(map[string]interface{}{})
	if err != nil {
		t.Fatalf("NewStruct returned error: %v", err)
	}
	grpcContext := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}}})
	service := &deviceTelemetryGRPCService{server: server}
	_, err = server.deviceCatalogGRPCAuthInterceptor()(grpcContext, request, &grpc.UnaryServerInfo{FullMethod: deviceTelemetryGRPCHeartbeatPath}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return service.Heartbeat(ctx, req.(*structpb.Struct))
	})
	if err != nil {
		t.Fatalf("Heartbeat returned error: %v", err)
	}
	report, ok := dataStore.GetDevicePosture("device-1")
	if !ok {
		t.Fatalf("posture report missing after heartbeat")
	}
	if !report.ReportedAt.After(time.Unix(1000, 0).UTC()) {
		t.Fatalf("reported_at was not touched: %s", report.ReportedAt)
	}
}

func TestDeviceCatalogGRPCInterceptorRequiresEnrolledMTLSIdentity(t *testing.T) {
	server, dataStore := newDeviceAPITestServer(t)
	certPEM, cert := newDeviceAPICertificate(t, "device-1", time.Now().Add(time.Hour))
	accessToken := newDeviceCatalogAccessToken(t, server, dataStore, "device-1", "admin")
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

func newDeviceCatalogAccessToken(t *testing.T, server *Server, dataStore *store.Store, deviceID, role string) string {
	t.Helper()
	dataStore.SaveUser(&models.User{
		ID:        "user-1",
		TenantID:  transportTestTenantID,
		Username:  "alice@example.test",
		Email:     "alice@example.test",
		Role:      role,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	token, err := server.pa.IdP.JWT.GenerateAuthToken("user-1", "alice@example.test", role, deviceID, "", false)
	if err != nil {
		t.Fatalf("GenerateAuthToken returned error: %v", err)
	}
	return token
}

func newDeviceAPITestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	dataStore := store.New(t.TempDir())
	if err := dataStore.InitDB(); err != nil {
		t.Fatalf("init store: %v", err)
	}
	dataStore.SaveTenant(&models.Tenant{
		ID:        transportTestTenantID,
		Name:      "Test Tenant",
		Domain:    "example.test",
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	t.Cleanup(func() { _ = dataStore.Close() })
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	policyAdmin := pa.NewPolicyAdministrator(cfg, dataStore)
	server := &Server{pa: policyAdmin, mtlsCAPool: x509.NewCertPool(), sessionGateways: make(map[string]string)}
	server.wireSessionDeleteSink()
	return server, dataStore
}

const transportTestTenantID = "tenant-1"

func newDeviceAPICertificate(t *testing.T, commonName string, notAfter time.Time) ([]byte, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return certPEM, cert
}
