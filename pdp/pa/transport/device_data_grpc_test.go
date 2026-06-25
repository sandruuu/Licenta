package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

func TestDeviceDataGRPCReportDeviceDataStoresRawData(t *testing.T) {
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
	token := newDeviceCatalogAccessToken(t, server, dataStore, "device-1", "user", clientCertificateFingerprint(cert))

	request, err := structpb.NewStruct(map[string]interface{}{
		"device_id":           "device-1",
		"hostname":            "host-1",
		"os":                  "Windows",
		"collected_at":        "2026-05-04T10:00:00Z",
		"reported_at":         "client-owned-value-is-ignored",
		"agent_session_id":    "sess-test",
		"agent_session_token": token,
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
	service := &deviceDataGRPCService{server: server}
	response, err := server.deviceCatalogGRPCAuthInterceptor()(grpcContext, request, &grpc.UnaryServerInfo{FullMethod: deviceDataGRPCReportDeviceDataPath}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return service.ReportDeviceData(ctx, req.(*structpb.Struct))
	})
	if err != nil {
		t.Fatalf("ReportDeviceData returned error: %v", err)
	}
	responseStruct, ok := response.(*structpb.Struct)
	if !ok {
		t.Fatalf("response type = %T, want *structpb.Struct", response)
	}
	reportedAt, err := time.Parse(time.RFC3339Nano, responseStruct.GetFields()["reported_at"].GetStringValue())
	if err != nil || reportedAt.IsZero() {
		t.Fatalf("reported_at response = %q, err=%v", responseStruct.GetFields()["reported_at"].GetStringValue(), err)
	}

	report, ok := dataStore.GetDeviceData("device-1")
	if !ok {
		t.Fatalf("device data report was not stored")
	}
	if report.Hostname != "host-1" || report.OS != "Windows" || len(report.Checks) != 1 || report.Checks[0].Status != "critical" {
		t.Fatalf("report = %+v", report)
	}
	if !report.ReportedAt.Equal(reportedAt) || report.CollectedAt.IsZero() {
		t.Fatalf("timestamps = collected_at=%s reported_at=%s response=%s", report.CollectedAt, report.ReportedAt, reportedAt)
	}
	if report.UserID != "user-1" || report.Username != "alice@example.test" || report.AgentSessionID != "sess-test" {
		t.Fatalf("user context = user_id=%q username=%q session=%q", report.UserID, report.Username, report.AgentSessionID)
	}
}

func TestDeviceDataGRPCReportDeviceDataRejectsDeviceMismatch(t *testing.T) {
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
	token := newDeviceCatalogAccessToken(t, server, dataStore, "device-1", "user", clientCertificateFingerprint(cert))

	request, err := structpb.NewStruct(map[string]interface{}{
		"device_id":           "device-2",
		"agent_session_id":    "sess-test",
		"agent_session_token": token,
		"checks":              []interface{}{},
	})
	if err != nil {
		t.Fatalf("NewStruct returned error: %v", err)
	}
	grpcContext := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}}})
	service := &deviceDataGRPCService{server: server}
	_, err = server.deviceCatalogGRPCAuthInterceptor()(grpcContext, request, &grpc.UnaryServerInfo{FullMethod: deviceDataGRPCReportDeviceDataPath}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return service.ReportDeviceData(ctx, req.(*structpb.Struct))
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status code = %s, want %s (err=%v)", status.Code(err), codes.PermissionDenied, err)
	}
	if _, ok := dataStore.GetDeviceData("device-2"); ok {
		t.Fatalf("mismatched device data report should not be stored")
	}
}

func TestDeviceDataGRPCReportDeviceDataRejectsMissingSessionToken(t *testing.T) {
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
		"device_id": "device-1",
		"checks":    []interface{}{},
	})
	if err != nil {
		t.Fatalf("NewStruct returned error: %v", err)
	}
	grpcContext := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}}})
	service := &deviceDataGRPCService{server: server}
	_, err = server.deviceCatalogGRPCAuthInterceptor()(grpcContext, request, &grpc.UnaryServerInfo{FullMethod: deviceDataGRPCReportDeviceDataPath}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return service.ReportDeviceData(ctx, req.(*structpb.Struct))
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("status code = %s, want %s (err=%v)", status.Code(err), codes.Unauthenticated, err)
	}
	if _, ok := dataStore.GetDeviceData("device-1"); ok {
		t.Fatalf("device data report without session token should not be stored")
	}
}

func TestDeviceDataGRPCReportDeviceDataRejectsSessionMismatch(t *testing.T) {
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
	token := newDeviceCatalogAccessToken(t, server, dataStore, "device-1", "user", clientCertificateFingerprint(cert))

	request, err := structpb.NewStruct(map[string]interface{}{
		"device_id":           "device-1",
		"agent_session_id":    "different-session",
		"agent_session_token": token,
		"checks":              []interface{}{},
	})
	if err != nil {
		t.Fatalf("NewStruct returned error: %v", err)
	}
	grpcContext := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}}})
	service := &deviceDataGRPCService{server: server}
	_, err = server.deviceCatalogGRPCAuthInterceptor()(grpcContext, request, &grpc.UnaryServerInfo{FullMethod: deviceDataGRPCReportDeviceDataPath}, func(ctx context.Context, req interface{}) (interface{}, error) {
		return service.ReportDeviceData(ctx, req.(*structpb.Struct))
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status code = %s, want %s (err=%v)", status.Code(err), codes.PermissionDenied, err)
	}
	if _, ok := dataStore.GetDeviceData("device-1"); ok {
		t.Fatalf("device data report with mismatched session should not be stored")
	}
}
