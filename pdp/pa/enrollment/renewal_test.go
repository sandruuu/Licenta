package enrollment

import (
	"errors"
	"testing"

	"pdp/models"
)

func TestServiceRenewDeviceCertificateUpdatesCertificateAndRejectsKeyMismatch(t *testing.T) {
	dataStore := newEnrollmentTestStore(t)
	service := NewService(dataStore)
	authority := newTestCertificateAuthority(t)
	service.SetCertificateAuthority(authority.signCSR, authority.revokeCertificate, func(component string) string {
		return "device-role"
	})

	deviceKey := testEnrollmentKey(t)
	enrollment, _, _, err := service.IssueDeviceCertificate(models.EnrollmentRequest{
		DeviceID:  "device-1",
		Component: "endpoint",
		Hostname:  "host-1",
		CSRPEM:    testEnrollmentCSRPEMWithKey(t, deviceKey, "device-1", "alice@example.com"),
	}, "", "alice", "user-1", "alice@example.com")
	if err != nil {
		t.Fatalf("IssueDeviceCertificate returned error: %v", err)
	}
	oldSerial := enrollment.CertSerial

	renewed, certPEM, err := service.RenewDeviceCertificate(models.EnrollmentRequest{
		DeviceID:  "device-1",
		Component: "endpoint",
		CSRPEM:    testEnrollmentCSRPEMWithKey(t, deviceKey, "device-1", "alice@example.com"),
	}, enrollment)
	if err != nil {
		t.Fatalf("RenewDeviceCertificate returned error: %v", err)
	}
	if renewed.ID != enrollment.ID || renewed.CertSerial == "" || renewed.CertSerial == oldSerial || string(certPEM) != renewed.CertPEM {
		t.Fatalf("unexpected renewed enrollment: %#v", renewed)
	}
	if len(authority.revokedSerials) != 1 || authority.revokedSerials[0] != oldSerial {
		t.Fatalf("revoked serials = %#v, want [%s]", authority.revokedSerials, oldSerial)
	}
	stored, found := dataStore.GetDeviceEnrollmentByComponent("device-1", "endpoint")
	if !found || stored.CertSerial != renewed.CertSerial {
		t.Fatalf("renewed enrollment was not persisted: found=%v stored=%#v", found, stored)
	}

	_, _, err = service.RenewDeviceCertificate(models.EnrollmentRequest{
		DeviceID:  "device-1",
		Component: "endpoint",
		CSRPEM:    testEnrollmentCSRPEM(t, "device-1", "alice@example.com"),
	}, renewed)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("RenewDeviceCertificate mismatched key error = %v, want ErrForbidden", err)
	}
	if len(authority.revokedSerials) != 1 || len(authority.roles) != 2 {
		t.Fatalf("mismatched key changed signing/revocation state: roles=%#v revoked=%#v", authority.roles, authority.revokedSerials)
	}
}
