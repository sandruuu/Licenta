package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agent/internal/service/catalog"
	"agent/internal/service/certificates"
	"agent/internal/service/deviceidentity"
	"agent/internal/service/enrollment"
	servicestate "agent/internal/service/state"
	"agent/internal/shared/ipc"
)

func TestFileEnrollmentStateStoreRoundTrip(t *testing.T) {
	now := time.Unix(2000, 0).UTC()
	path := filepath.Join(t.TempDir(), "state", "agent-enrollment-state.json")
	store := servicestate.NewEnrollmentFileStore(path, func() time.Time { return now })
	state := servicestate.Enrollment{
		Version:             servicestate.EnrollmentFileVersion,
		EnrollmentState:     ipc.EnrollmentStateEnrolled,
		DeviceID:            "device-1",
		DeviceIDSource:      deviceidentity.DeviceIDSourceTPMEKPublicSHA256,
		ActiveUserSID:       "S-1-5-21-1",
		KeyName:             "ZTNA_DeviceKey",
		KeyProvider:         deviceidentity.MicrosoftPlatformCryptoProvider,
		CertificateSHA256:   "cert-sha",
		CertificateNotAfter: now.Add(time.Hour),
		LastAcceptedAt:      now.Add(-time.Minute),
	}
	if err := store.Save(context.Background(), state); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}
	loaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if loaded.DeviceID != state.DeviceID || loaded.KeyName != state.KeyName || loaded.CertificateSHA256 != state.CertificateSHA256 || !loaded.CertificateNotAfter.Equal(state.CertificateNotAfter) || !loaded.UpdatedAt.Equal(now) {
		t.Fatalf("loaded state = %+v", loaded)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted state: %v", err)
	}
	if strings.Contains(string(data), "access_token") || strings.Contains(string(data), "enrollment_token") {
		t.Fatalf("persisted state contains token material: %s", data)
	}
}

func TestFileCatalogCacheStoreRoundTrip(t *testing.T) {
	now := time.Unix(2500, 0).UTC()
	path := filepath.Join(t.TempDir(), "state", "agent-catalog-cache.json")
	store := servicestate.NewCatalogCacheFileStore(path, func() time.Time { return now })
	cache := servicestate.CatalogCache{
		Version:        servicestate.CatalogCacheFileVersion,
		DeviceID:       "device-1",
		CatalogVersion: "v1",
		PolicyEpoch:    "epoch-1",
		DNSSuffixes:    []string{"Example.Test", "example.test", ".internal.test"},
		Resources:      []catalog.Resource{{FQDN: "Admin.Example.Test.", ResourceID: "res-1", Protocol: "HTTPS", Port: 443}},
		TTLSeconds:     300,
		FetchedAt:      now.Add(-time.Minute),
		ExpiresAt:      now.Add(4 * time.Minute),
	}
	if err := store.Save(context.Background(), cache); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}
	loaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if loaded.DeviceID != "device-1" || loaded.CatalogVersion != "v1" || loaded.PolicyEpoch != "epoch-1" || len(loaded.DNSSuffixes) != 2 || loaded.DNSSuffixes[0] != "example.test" || loaded.DNSSuffixes[1] != "internal.test" || len(loaded.Resources) != 1 || loaded.Resources[0].FQDN != "admin.example.test" || !loaded.UpdatedAt.Equal(now) {
		t.Fatalf("loaded cache = %+v", loaded)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted cache: %v", err)
	}
	if strings.Contains(string(data), "access_token") || strings.Contains(string(data), "refresh_token") || strings.Contains(string(data), "header.payload.signature") {
		t.Fatalf("persisted catalog cache leaked token material: %s", data)
	}
}

func TestServiceRestoresCatalogCacheAndReappliesDNS(t *testing.T) {
	now := time.Unix(4500, 0).UTC()
	certificate, certificateSHA256 := testMachineTLSCertificate(t, "device-1", now)
	enrollmentStore := servicestate.NewEnrollmentFileStore(filepath.Join(t.TempDir(), "agent-enrollment-state.json"), func() time.Time { return now })
	if err := enrollmentStore.Save(context.Background(), servicestate.Enrollment{
		Version:           servicestate.EnrollmentFileVersion,
		EnrollmentState:   ipc.EnrollmentStateEnrolled,
		DeviceID:          "device-1",
		DeviceIDSource:    deviceidentity.DeviceIDSourceTPMEKPublicSHA256,
		ActiveUserSID:     "S-1-5-21-1",
		KeyName:           "ZTNA_DeviceKey",
		KeyProvider:       deviceidentity.MicrosoftPlatformCryptoProvider,
		CertificateSHA256: certificateSHA256,
		LastAcceptedAt:    now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("Save enrollment state returned error: %v", err)
	}
	catalogStore := servicestate.NewCatalogCacheFileStore(filepath.Join(t.TempDir(), "agent-catalog-cache.json"), func() time.Time { return now })
	if err := catalogStore.Save(context.Background(), servicestate.CatalogCache{
		Version:        servicestate.CatalogCacheFileVersion,
		DeviceID:       "device-1",
		CatalogVersion: "v-cache",
		PolicyEpoch:    "epoch-cache",
		DNSSuffixes:    []string{"example.test"},
		Resources:      []catalog.Resource{{FQDN: "cached.example.test", ResourceID: "res-cache", Protocol: "https", Port: 443}},
		TTLSeconds:     300,
		FetchedAt:      now.Add(-time.Minute),
		ExpiresAt:      now.Add(4 * time.Minute),
	}); err != nil {
		t.Fatalf("Save catalog cache returned error: %v", err)
	}
	dnsConfigurator := &fakeDNSConfigurator{}
	service := newTestService(serviceTestOptions{
		AuthorizedUserSID: "S-1-5-21-1",
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:             func() time.Time { return now },
		IdentityProvider:  testIdentityProviderWithDevice("S-1-5-21-1", "device-1"),
		StateStore:        enrollmentStore,
		CatalogCacheStore: catalogStore,
		DNSConfigurator:   dnsConfigurator,
		CertificateLoader: func(context.Context, deviceidentity.MachineCertificateOptions) (tls.Certificate, error) {
			return certificate, nil
		},
	})
	status := service.status()
	if status.CatalogStatus != catalogStatusReady || status.CatalogVersion != "v-cache" || status.CatalogPolicyEpoch != "epoch-cache" || status.CatalogDNSSuffixCount != 1 || status.CatalogResourceCount != 1 || status.SyntheticResourceCount != 1 {
		t.Fatalf("status = %+v", status)
	}
	if len(dnsConfigurator.configs) != 1 || len(dnsConfigurator.configs[0].DNSSuffixes) != 1 || dnsConfigurator.configs[0].DNSSuffixes[0] != "example.test" {
		t.Fatalf("dns configs = %+v", dnsConfigurator.configs)
	}
}

func TestServicePersistsEnrollmentMetadataAfterRunnerSuccess(t *testing.T) {
	now := time.Unix(3000, 0).UTC()
	statePath := filepath.Join(t.TempDir(), "agent-enrollment-state.json")
	store := servicestate.NewEnrollmentFileStore(statePath, func() time.Time { return now })
	runner := &fakeEnrollmentRunner{result: &enrollment.RunnerResult{EnrollmentID: "enroll-1", CertificateSHA256: "cert-sha", CertificateNotAfter: now.Add(time.Hour)}}
	service := newTestService(serviceTestOptions{
		AuthorizedUserSID: "S-1-5-21-1",
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:             func() time.Time { return now },
		IdentityProvider:  testIdentityProviderWithDevice("S-1-5-21-1", "device-1"),
		EnrollmentRunner:  runner,
		StateStore:        store,
		EnrollmentValidator: fakeEnrollmentValidator{result: &enrollment.ValidationResult{
			DeviceID: "device-1",
			Nonce:    "nonce-1",
			UserSID:  "S-1-5-21-1",
		}},
	})
	service.enrollment.Nonce = "nonce-1"
	request, err := ipc.NewRequest("req-1", ipc.OperationStartEnrollment, ipc.StartEnrollmentRequest{
		AccessToken:          "access.payload.signature",
		AccessTokenExpiresAt: now.Add(time.Hour),
		Nonce:                "nonce-1",
		DeviceID:             "device-1",
		UserSID:              "S-1-5-21-1",
		KeyName:              "ZTNA_DeviceKey",
		SentAt:               now,
	})
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}
	response, err := service.HandleIPC(context.Background(), request)
	if err != nil {
		t.Fatalf("HandleIPC returned error: %v", err)
	}
	if !response.OK {
		t.Fatalf("response error = %+v", response.Error)
	}
	loaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if loaded.EnrollmentState != ipc.EnrollmentStateEnrolled || loaded.DeviceID != "device-1" || loaded.CertificateSHA256 != "cert-sha" || !loaded.CertificateNotAfter.Equal(now.Add(time.Hour)) {
		t.Fatalf("loaded state = %+v", loaded)
	}
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read persisted state: %v", err)
	}
	if strings.Contains(string(data), "access.payload.signature") || strings.Contains(string(data), "access_token") || strings.Contains(string(data), "header.payload.signature") {
		t.Fatalf("persisted state leaked token material: %s", data)
	}
}

func TestServiceRestoresEnrollmentStateFromMachineStoreCertificate(t *testing.T) {
	now := time.Unix(4000, 0).UTC()
	certificate, certificateSHA256 := testMachineTLSCertificate(t, "device-1", now)
	store := servicestate.NewEnrollmentFileStore(filepath.Join(t.TempDir(), "agent-enrollment-state.json"), func() time.Time { return now })
	if err := store.Save(context.Background(), servicestate.Enrollment{
		Version:           servicestate.EnrollmentFileVersion,
		EnrollmentState:   ipc.EnrollmentStateEnrolled,
		DeviceID:          "device-1",
		DeviceIDSource:    deviceidentity.DeviceIDSourceTPMEKPublicSHA256,
		ActiveUserSID:     "S-1-5-21-1",
		KeyName:           "ZTNA_DeviceKey",
		KeyProvider:       deviceidentity.MicrosoftPlatformCryptoProvider,
		CertificateSHA256: certificateSHA256,
		LastAcceptedAt:    now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}
	service := newTestService(serviceTestOptions{
		AuthorizedUserSID: "S-1-5-21-1",
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:             func() time.Time { return now },
		IdentityProvider:  testIdentityProviderWithDevice("S-1-5-21-1", "device-1"),
		StateStore:        store,
		CertificateLoader: func(context.Context, deviceidentity.MachineCertificateOptions) (tls.Certificate, error) {
			return certificate, nil
		},
	})
	status := service.status()
	if status.EnrollmentState != ipc.EnrollmentStateEnrolled || status.CertificateSHA256 != certificateSHA256 || status.KeyName != "ZTNA_DeviceKey" || !status.CertificateExpiresAt.Equal(certificate.Leaf.NotAfter.UTC()) {
		t.Fatalf("status = %+v", status)
	}
}

func TestServiceRenewsCertificateWhenExpiryWithinWindow(t *testing.T) {
	now := time.Unix(6000, 0).UTC()
	certificate, certificateSHA256 := testMachineTLSCertificate(t, "device-1", now)
	renewedExpiresAt := now.Add(24 * time.Hour)
	renewer := &fakeEnrollmentRenewer{result: &enrollment.RunnerResult{CertificateSHA256: "renewed-cert-sha", CertificateNotAfter: renewedExpiresAt}}
	store := servicestate.NewEnrollmentFileStore(filepath.Join(t.TempDir(), "agent-enrollment-state.json"), func() time.Time { return now })
	service := newTestService(serviceTestOptions{
		AuthorizedUserSID:      "S-1-5-21-1",
		Logger:                 slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:                  func() time.Time { return now },
		IdentityProvider:       testIdentityProviderWithDevice("S-1-5-21-1", "device-1"),
		StateStore:             store,
		EnrollmentRenewer:      renewer,
		CertificateRenewBefore: 12 * time.Hour,
		CertificateLoader: func(_ context.Context, options deviceidentity.MachineCertificateOptions) (tls.Certificate, error) {
			if options.DeviceID != "device-1" || options.KeyName != "ZTNA_DeviceKey" {
				t.Fatalf("certificate loader options = %+v", options)
			}
			return certificate, nil
		},
	})
	service.enrollment.State = ipc.EnrollmentStateEnrolled
	service.enrollment.DeviceID = "device-1"
	service.enrollment.KeyName = "ZTNA_DeviceKey"
	service.enrollment.KeyProvider = deviceidentity.MicrosoftPlatformCryptoProvider
	service.enrollment.CertificateSHA256 = certificateSHA256
	service.enrollment.CertificateNotAfter = certificate.Leaf.NotAfter.UTC()

	renewed, err := service.renewCertificateIfNeeded(context.Background(), "test")
	if err != nil {
		t.Fatalf("renewCertificateIfNeeded returned error: %v", err)
	}
	if !renewed || renewer.calls != 1 || renewer.input.DeviceID != "device-1" || len(renewer.input.CurrentCertificate.Certificate) == 0 {
		t.Fatalf("renewed=%t renewer=%+v", renewed, renewer)
	}
	status := service.status()
	if status.CertificateSHA256 != "renewed-cert-sha" || !status.CertificateExpiresAt.Equal(renewedExpiresAt) || status.LastError != "" {
		t.Fatalf("status = %+v", status)
	}
	loaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if loaded.CertificateSHA256 != "renewed-cert-sha" || !loaded.CertificateNotAfter.Equal(renewedExpiresAt) {
		t.Fatalf("loaded state = %+v", loaded)
	}
}

func TestServiceDoesNotRenewFreshCertificate(t *testing.T) {
	now := time.Unix(7000, 0).UTC()
	certificate, certificateSHA256 := testMachineTLSCertificateExpiresAt(t, "device-1", now, now.Add(24*time.Hour))
	renewer := &fakeEnrollmentRenewer{result: &enrollment.RunnerResult{CertificateSHA256: "renewed-cert-sha", CertificateNotAfter: now.Add(48 * time.Hour)}}
	store := servicestate.NewEnrollmentFileStore(filepath.Join(t.TempDir(), "agent-enrollment-state.json"), func() time.Time { return now })
	service := newTestService(serviceTestOptions{
		AuthorizedUserSID:      "S-1-5-21-1",
		Logger:                 slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:                  func() time.Time { return now },
		IdentityProvider:       testIdentityProviderWithDevice("S-1-5-21-1", "device-1"),
		StateStore:             store,
		EnrollmentRenewer:      renewer,
		CertificateRenewBefore: 12 * time.Hour,
		CertificateLoader: func(context.Context, deviceidentity.MachineCertificateOptions) (tls.Certificate, error) {
			return certificate, nil
		},
	})
	service.enrollment.State = ipc.EnrollmentStateEnrolled
	service.enrollment.DeviceID = "device-1"
	service.enrollment.KeyName = "ZTNA_DeviceKey"
	service.enrollment.KeyProvider = deviceidentity.MicrosoftPlatformCryptoProvider
	service.enrollment.CertificateSHA256 = certificateSHA256

	renewed, err := service.renewCertificateIfNeeded(context.Background(), "test")
	if err != nil {
		t.Fatalf("renewCertificateIfNeeded returned error: %v", err)
	}
	if renewed || renewer.calls != 0 {
		t.Fatalf("renewed=%t renewer calls=%d", renewed, renewer.calls)
	}
	status := service.status()
	if status.CertificateSHA256 != certificateSHA256 || !status.CertificateExpiresAt.Equal(certificate.Leaf.NotAfter.UTC()) {
		t.Fatalf("status = %+v", status)
	}
}

func TestServiceDoesNotRestoreWhenCertificateFingerprintDiffers(t *testing.T) {
	now := time.Unix(5000, 0).UTC()
	certificate, _ := testMachineTLSCertificate(t, "device-1", now)
	store := servicestate.NewEnrollmentFileStore(filepath.Join(t.TempDir(), "agent-enrollment-state.json"), func() time.Time { return now })
	if err := store.Save(context.Background(), servicestate.Enrollment{
		Version:           servicestate.EnrollmentFileVersion,
		EnrollmentState:   ipc.EnrollmentStateEnrolled,
		DeviceID:          "device-1",
		DeviceIDSource:    deviceidentity.DeviceIDSourceTPMEKPublicSHA256,
		ActiveUserSID:     "S-1-5-21-1",
		KeyName:           "ZTNA_DeviceKey",
		KeyProvider:       deviceidentity.MicrosoftPlatformCryptoProvider,
		CertificateSHA256: "different-cert-sha",
	}); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}
	service := newTestService(serviceTestOptions{
		AuthorizedUserSID: "S-1-5-21-1",
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:             func() time.Time { return now },
		IdentityProvider:  testIdentityProviderWithDevice("S-1-5-21-1", "device-1"),
		StateStore:        store,
		CertificateLoader: func(context.Context, deviceidentity.MachineCertificateOptions) (tls.Certificate, error) {
			return certificate, nil
		},
	})
	status := service.status()
	if status.EnrollmentState == ipc.EnrollmentStateEnrolled {
		t.Fatalf("service restored enrollment despite mismatched certificate: %+v", status)
	}
	if !strings.Contains(status.LastError, "certificate_sha256") {
		t.Fatalf("status LastError = %q", status.LastError)
	}
}

func testMachineTLSCertificate(t *testing.T, deviceID string, now time.Time) (tls.Certificate, string) {
	t.Helper()
	return testMachineTLSCertificateExpiresAt(t, deviceID, now, now.Add(time.Hour))
}

func testMachineTLSCertificateExpiresAt(t *testing.T, deviceID string, now, notAfter time.Time) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: deviceID},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate returned error: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate returned error: %v", err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	certificateSHA256, err := certificates.SHA256(certificate)
	if err != nil {
		t.Fatalf("tlsCertificateSHA256 returned error: %v", err)
	}
	return certificate, certificateSHA256
}
