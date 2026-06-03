package enrollment

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"agent/internal/shared/ipc"
)

func TestRenewCertificateIfNeededSkipsBeforeRenewalWindow(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	store := &testEnrollmentStore{record: enrolledRecord(now.Add(13 * time.Hour))}
	client := &recordingRenewalClient{}
	manager := NewManager(Config{
		CertificateRenewBefore:  12 * time.Hour,
		CertificateRenewTimeout: time.Second,
	}, Dependencies{
		Store:          store,
		RenewalClient:  client,
		DeviceIdentity: &renewalTestIdentity{},
		Clock:          func() time.Time { return now },
	})

	renewed, err := manager.RenewCertificateIfNeeded(context.Background())
	if err != nil {
		t.Fatalf("RenewCertificateIfNeeded returned error: %v", err)
	}
	if renewed {
		t.Fatal("RenewCertificateIfNeeded renewed before the configured renewal window")
	}
	if client.calls != 0 {
		t.Fatalf("renewal client calls = %d, want 0", client.calls)
	}
	if store.record.DeviceCertThumbprint != "old-thumb" {
		t.Fatalf("thumbprint changed unexpectedly: %q", store.record.DeviceCertThumbprint)
	}
}

func TestRenewCertificateIfNeededRenewsAndSavesUpdatedRecord(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	renewedExpiry := now.Add(24 * time.Hour)
	store := &testEnrollmentStore{record: enrolledRecord(now.Add(2 * time.Hour))}
	identity := &renewalTestIdentity{
		renewalCSR: EnrollmentCSR{
			KeyName:  "device-key",
			Provider: "provider",
			CSRPEM:   "renewal-csr",
			SPKIHash: "spki-hash",
		},
		installed: InstalledCertificate{Thumbprint: "installed-thumb", ExpiresAt: renewedExpiry},
	}
	client := &recordingRenewalClient{
		response: CertificateRenewalResponse{
			CertificatePEM:        "renewed-cert",
			CertificateChainPEM:   "renewed-ca",
			CertificateThumbprint: "new-thumb",
			ExpiresAt:             renewedExpiry,
		},
	}
	manager := NewManager(Config{
		CertificateRenewBefore:  12 * time.Hour,
		CertificateRenewTimeout: time.Second,
	}, Dependencies{
		Store:          store,
		RenewalClient:  client,
		DeviceIdentity: identity,
		Clock:          func() time.Time { return now },
	})

	renewed, err := manager.RenewCertificateIfNeeded(context.Background())
	if err != nil {
		t.Fatalf("RenewCertificateIfNeeded returned error: %v", err)
	}
	if !renewed {
		t.Fatal("RenewCertificateIfNeeded did not renew inside the configured renewal window")
	}
	if client.calls != 1 {
		t.Fatalf("renewal client calls = %d, want 1", client.calls)
	}
	if client.request.DeviceID != "device-1" || client.request.Component != "endpoint" || client.request.CSRPEM != "renewal-csr" || client.request.PublicKeyFingerprint != "spki-hash" {
		t.Fatalf("renewal request = %+v", client.request)
	}
	if identity.installedRequest.CertificatePEM != "renewed-cert" || identity.installedRequest.CertificateChainPEM != "renewed-ca" {
		t.Fatalf("install request = %+v", identity.installedRequest)
	}
	if store.record.DeviceCertThumbprint != "new-thumb" || store.record.DeviceCertificateChainPEM != "renewed-ca" || !store.record.CertificateExpiry.Equal(renewedExpiry) {
		t.Fatalf("saved record = %+v", store.record)
	}
	snapshot := manager.Snapshot()
	if snapshot.State != ipc.EnrollmentStateEnrolled || snapshot.DeviceID != "device-1" {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}

func enrolledRecord(expiresAt time.Time) EnrollmentRecord {
	return EnrollmentRecord{
		EnrollmentState:           ipc.EnrollmentStateEnrolled,
		DeviceID:                  "device-1",
		DeviceKeyName:             "device-key",
		DeviceKeyProvider:         "provider",
		DeviceCertThumbprint:      "old-thumb",
		DeviceCertificateChainPEM: "old-ca",
		CertificateExpiry:         expiresAt,
	}
}

type testEnrollmentStore struct {
	record EnrollmentRecord
}

func (store *testEnrollmentStore) Load(context.Context) (EnrollmentRecord, error) {
	return store.record, nil
}

func (store *testEnrollmentStore) Save(_ context.Context, record EnrollmentRecord) error {
	store.record = record
	return nil
}

type recordingRenewalClient struct {
	calls    int
	request  CertificateRenewalRequest
	response CertificateRenewalResponse
	err      error
}

func (client *recordingRenewalClient) RenewCertificate(_ context.Context, _ EnrollmentRecord, _ tls.Certificate, request CertificateRenewalRequest) (CertificateRenewalResponse, error) {
	client.calls++
	client.request = request
	if client.err != nil {
		return CertificateRenewalResponse{}, client.err
	}
	return client.response, nil
}

type renewalTestIdentity struct {
	renewalCSR       EnrollmentCSR
	installed        InstalledCertificate
	installedRequest InstallCertificateRequest
}

func (identity renewalTestIdentity) CreateEnrollmentCSR(context.Context, string) (EnrollmentCSR, error) {
	return EnrollmentCSR{}, nil
}

func (identity *renewalTestIdentity) CreateCertificateRenewalCSR(context.Context, string, string) (EnrollmentCSR, error) {
	if identity.renewalCSR.CSRPEM != "" {
		return identity.renewalCSR, nil
	}
	return EnrollmentCSR{KeyName: "device-key", Provider: "provider", CSRPEM: "renewal-csr", SPKIHash: "spki-hash"}, nil
}

func (identity renewalTestIdentity) SignEnrollmentProof(context.Context, string, []byte) ([]byte, error) {
	return nil, nil
}

func (identity *renewalTestIdentity) InstallDeviceCertificate(_ context.Context, request InstallCertificateRequest) (InstalledCertificate, error) {
	identity.installedRequest = request
	if identity.installed.Thumbprint != "" || !identity.installed.ExpiresAt.IsZero() {
		return identity.installed, nil
	}
	return InstalledCertificate{Thumbprint: "installed-thumb", ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (identity renewalTestIdentity) CheckLocalEnrollment(context.Context, EnrollmentRecord) (LocalEnrollmentCheck, error) {
	return LocalEnrollmentCheck{Enrolled: true}, nil
}

func (identity renewalTestIdentity) ClientCertificate(context.Context, EnrollmentRecord) (tls.Certificate, func(), error) {
	return tls.Certificate{}, func() {}, nil
}
