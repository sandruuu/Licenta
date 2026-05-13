package enrollment

import (
	"testing"

	"pdp/models"
)

func TestServiceIssueDeviceCertificateReusesSameKeyAndRevokesChangedKey(t *testing.T) {
	dataStore := newEnrollmentTestStore(t)
	service := NewService(dataStore)
	authority := newTestCertificateAuthority(t)
	service.SetCertificateAuthority(authority.signCSR, authority.revokeCertificate, func(component string) string {
		if component != "endpoint" {
			t.Fatalf("device role received component %q, want endpoint", component)
		}
		return "device-role"
	})

	request := models.EnrollmentRequest{
		DeviceID:  "device-1",
		Component: "tunnel",
		Hostname:  "host-1",
		CSRPEM:    testEnrollmentCSRPEM(t, "device-1", "alice@example.com"),
	}
	enrollment, certPEM, reused, err := service.IssueDeviceCertificate(request, "", "alice", "user-1", "alice@example.com")
	if err != nil {
		t.Fatalf("IssueDeviceCertificate returned error: %v", err)
	}
	if reused {
		t.Fatalf("first enrollment was marked reused")
	}
	if enrollment.Component != "endpoint" {
		t.Fatalf("component = %q, want endpoint", enrollment.Component)
	}
	if enrollment.Status != "approved" || enrollment.CertSerial == "" || string(certPEM) != enrollment.CertPEM {
		t.Fatalf("unexpected approved enrollment: %#v", enrollment)
	}
	if len(authority.roles) != 1 || authority.roles[0] != "device-role" {
		t.Fatalf("sign roles = %#v, want [device-role]", authority.roles)
	}

	reusedEnrollment, reusedCertPEM, reused, err := service.IssueDeviceCertificate(request, "", "alice", "user-1", "alice@example.com")
	if err != nil {
		t.Fatalf("IssueDeviceCertificate reuse returned error: %v", err)
	}
	if !reused || reusedEnrollment.ID != enrollment.ID || string(reusedCertPEM) != enrollment.CertPEM {
		t.Fatalf("same key was not reused")
	}
	if len(authority.roles) != 1 {
		t.Fatalf("same key triggered another certificate signing")
	}

	request.CSRPEM = testEnrollmentCSRPEM(t, "device-1", "alice@example.com")
	changedEnrollment, _, reused, err := service.IssueDeviceCertificate(request, "", "alice", "user-1", "alice@example.com")
	if err != nil {
		t.Fatalf("IssueDeviceCertificate changed key returned error: %v", err)
	}
	if reused || changedEnrollment.ID == enrollment.ID {
		t.Fatalf("changed key was not issued as a new enrollment")
	}
	if len(authority.roles) != 2 {
		t.Fatalf("changed key did not trigger a new certificate signing")
	}
	if len(authority.revokedSerials) != 1 || authority.revokedSerials[0] != enrollment.CertSerial {
		t.Fatalf("revoked serials = %#v, want [%s]", authority.revokedSerials, enrollment.CertSerial)
	}
}
