package pdpclient

import (
	"context"
	"crypto/tls"
	"testing"

	"agent/internal/service/enrollment"
)

func TestClientReusesConnectionForSameDeviceCertificate(t *testing.T) {
	cleanupCalls := 0
	client := New(Config{PDPGRPCEndpoint: "pdp.example.test:443"}, fakeDeviceIdentity{cleanupCalls: &cleanupCalls})
	record := enrollment.EnrollmentRecord{DeviceID: "device-1", DeviceCertThumbprint: "thumb-1"}

	first, err := client.Connection(context.Background(), record)
	if err != nil {
		t.Fatalf("Connection returned error: %v", err)
	}
	second, err := client.Connection(context.Background(), record)
	if err != nil {
		t.Fatalf("Connection returned error: %v", err)
	}
	if first != second {
		t.Fatalf("connection was not reused for the same device certificate")
	}
	if cleanupCalls != 0 {
		t.Fatalf("cleanup calls = %d, want 0", cleanupCalls)
	}

	third, err := client.Connection(context.Background(), enrollment.EnrollmentRecord{DeviceID: "device-1", DeviceCertThumbprint: "thumb-2"})
	if err != nil {
		t.Fatalf("Connection after certificate change returned error: %v", err)
	}
	if third == first {
		t.Fatalf("connection was reused after certificate thumbprint changed")
	}
	if cleanupCalls != 1 {
		t.Fatalf("cleanup calls after rotation = %d, want 1", cleanupCalls)
	}

	if err := client.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if cleanupCalls != 2 {
		t.Fatalf("cleanup calls after close = %d, want 2", cleanupCalls)
	}
}

func TestClientDedicatedConnectionDoesNotReuseSharedConnection(t *testing.T) {
	cleanupCalls := 0
	client := New(Config{PDPGRPCEndpoint: "pdp.example.test:443"}, fakeDeviceIdentity{cleanupCalls: &cleanupCalls})
	record := enrollment.EnrollmentRecord{DeviceID: "device-1", DeviceCertThumbprint: "thumb-1"}

	shared, err := client.Connection(context.Background(), record)
	if err != nil {
		t.Fatalf("Connection returned error: %v", err)
	}
	dedicated, cleanup, err := client.DedicatedConnection(context.Background(), record)
	if err != nil {
		t.Fatalf("DedicatedConnection returned error: %v", err)
	}
	if dedicated == shared {
		t.Fatalf("dedicated connection reused the shared connection")
	}
	cleanup()
	if cleanupCalls != 1 {
		t.Fatalf("cleanup calls after dedicated cleanup = %d, want 1", cleanupCalls)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if cleanupCalls != 2 {
		t.Fatalf("cleanup calls after shared close = %d, want 2", cleanupCalls)
	}
}

type fakeDeviceIdentity struct {
	cleanupCalls *int
}

func (identity fakeDeviceIdentity) CreateEnrollmentCSR(context.Context, string) (enrollment.EnrollmentCSR, error) {
	return enrollment.EnrollmentCSR{}, nil
}

func (identity fakeDeviceIdentity) CreateCertificateRenewalCSR(context.Context, string, string) (enrollment.EnrollmentCSR, error) {
	return enrollment.EnrollmentCSR{}, nil
}

func (identity fakeDeviceIdentity) SignEnrollmentProof(context.Context, string, []byte) ([]byte, error) {
	return nil, nil
}

func (identity fakeDeviceIdentity) InstallDeviceCertificate(context.Context, enrollment.InstallCertificateRequest) (enrollment.InstalledCertificate, error) {
	return enrollment.InstalledCertificate{}, nil
}

func (identity fakeDeviceIdentity) CheckLocalEnrollment(context.Context, enrollment.EnrollmentRecord) (enrollment.LocalEnrollmentCheck, error) {
	return enrollment.LocalEnrollmentCheck{Enrolled: true}, nil
}

func (identity fakeDeviceIdentity) ClientCertificate(context.Context, enrollment.EnrollmentRecord) (tls.Certificate, func(), error) {
	return tls.Certificate{}, func() {
		if identity.cleanupCalls != nil {
			*identity.cleanupCalls = *identity.cleanupCalls + 1
		}
	}, nil
}
