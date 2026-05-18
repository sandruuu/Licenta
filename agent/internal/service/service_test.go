package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"agent/internal/service/catalog"
	"agent/internal/service/deviceidentity"
	"agent/internal/service/dnscontrol"
	"agent/internal/service/enrollment"
	agentnetwork "agent/internal/service/network"
	"agent/internal/service/relay"
	servicestate "agent/internal/service/state"
	"agent/internal/shared/ipc"
)

type serviceTestOptions struct {
	AuthorizedUserSID          string
	PAURL                      string
	CloudCertSHA256            string
	CAFile                     string
	PostureInterval            time.Duration
	CriticalInterval           time.Duration
	HeartbeatInterval          time.Duration
	PostureReportTimeout       time.Duration
	CatalogInterval            time.Duration
	CatalogCacheTTL            time.Duration
	CatalogRetryBackoff        []time.Duration
	AccessTokenExpirySkew      time.Duration
	DNSServer                  string
	TUNEnabled                 bool
	TUNName                    string
	TUNIP                      string
	TUNNetmask                 string
	TUNRouteCIDR               string
	ProcessIdentity            bool
	CertificateRenewalInterval time.Duration
	CertificateRenewBefore     time.Duration
	CertificateRenewalTimeout  time.Duration
	PARequestTimeout           time.Duration
	EnrollmentRateLimitMax     int
	EnrollmentRateLimitWindow  time.Duration
	Logger                     *slog.Logger
	ListenerFactory            func(string) (net.Listener, error)
	EnrollmentValidator        EnrollmentValidator
	IdentityProvider           deviceidentity.Provider
	PostureCollector           DevicePostureCollector
	PostureReporter            DevicePostureReporter
	CatalogClient              DeviceCatalogClient
	ResourceAuthorizer         relay.ResourceAuthorizer
	DNSConfigurator            DNSConfigurator
	SyntheticResolver          SyntheticResolver
	DNSResolverServer          DNSResolverServer
	NetworkManager             NetworkManager
	EnrollmentRunner           EnrollmentRunner
	EnrollmentRenewer          EnrollmentRenewer
	StateStore                 servicestate.EnrollmentStore
	CatalogCacheStore          servicestate.CatalogCacheStore
	CertificateLoader          MachineCertificateLoader
	Clock                      func() time.Time
}

func newTestService(options serviceTestOptions) *Service {
	if options.PostureReportTimeout <= 0 {
		options.PostureReportTimeout = 30 * time.Second
	}
	if options.CatalogCacheTTL <= 0 {
		options.CatalogCacheTTL = 5 * time.Minute
	}
	if len(options.CatalogRetryBackoff) == 0 {
		options.CatalogRetryBackoff = []time.Duration{5 * time.Minute, 10 * time.Minute, 15 * time.Minute, 30 * time.Minute}
	}
	if options.AccessTokenExpirySkew <= 0 {
		options.AccessTokenExpirySkew = 30 * time.Second
	}
	if options.CertificateRenewalTimeout <= 0 {
		options.CertificateRenewalTimeout = 30 * time.Second
	}
	if options.PARequestTimeout <= 0 {
		options.PARequestTimeout = 10 * time.Second
	}
	if options.EnrollmentRateLimitMax <= 0 {
		options.EnrollmentRateLimitMax = 3
	}
	if options.EnrollmentRateLimitWindow <= 0 {
		options.EnrollmentRateLimitWindow = time.Minute
	}
	return New(Config{
		AuthorizedUserSID:          options.AuthorizedUserSID,
		PAURL:                      options.PAURL,
		CloudCertSHA256:            options.CloudCertSHA256,
		CAFile:                     options.CAFile,
		PostureInterval:            options.PostureInterval,
		CriticalInterval:           options.CriticalInterval,
		HeartbeatInterval:          options.HeartbeatInterval,
		PostureReportTimeout:       options.PostureReportTimeout,
		CatalogInterval:            options.CatalogInterval,
		CatalogCacheTTL:            options.CatalogCacheTTL,
		CatalogRetryBackoff:        options.CatalogRetryBackoff,
		AccessTokenExpirySkew:      options.AccessTokenExpirySkew,
		DNSServer:                  options.DNSServer,
		TUNEnabled:                 options.TUNEnabled,
		TUNName:                    options.TUNName,
		TUNIP:                      options.TUNIP,
		TUNNetmask:                 options.TUNNetmask,
		TUNRouteCIDR:               options.TUNRouteCIDR,
		ProcessIdentity:            options.ProcessIdentity,
		CertificateRenewalInterval: options.CertificateRenewalInterval,
		CertificateRenewBefore:     options.CertificateRenewBefore,
		CertificateRenewalTimeout:  options.CertificateRenewalTimeout,
		PARequestTimeout:           options.PARequestTimeout,
		EnrollmentRateLimitMax:     options.EnrollmentRateLimitMax,
		EnrollmentRateLimitWindow:  options.EnrollmentRateLimitWindow,
	}, Dependencies{
		Logger:              options.Logger,
		ListenerFactory:     options.ListenerFactory,
		EnrollmentValidator: options.EnrollmentValidator,
		IdentityProvider:    options.IdentityProvider,
		PostureCollector:    options.PostureCollector,
		PostureReporter:     options.PostureReporter,
		CatalogClient:       options.CatalogClient,
		ResourceAuthorizer:  options.ResourceAuthorizer,
		DNSConfigurator:     options.DNSConfigurator,
		SyntheticResolver:   options.SyntheticResolver,
		DNSResolverServer:   options.DNSResolverServer,
		NetworkManager:      options.NetworkManager,
		EnrollmentRunner:    options.EnrollmentRunner,
		EnrollmentRenewer:   options.EnrollmentRenewer,
		StateStore:          options.StateStore,
		CatalogCacheStore:   options.CatalogCacheStore,
		CertificateLoader:   options.CertificateLoader,
		Clock:               options.Clock,
	})
}

func TestServiceHandlesPing(t *testing.T) {
	service := newTestService(serviceTestOptions{AuthorizedUserSID: "S-1-5-21-1", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	service.transition(StateRunning)
	request, err := ipc.NewRequest("req-1", ipc.OperationPing, ipc.PingRequest{Message: "hello", TrayPID: 22, SentAt: time.Now().UTC()})
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
	var ping ipc.PingResponse
	if err := ipc.DecodeBody(response.Body, &ping); err != nil {
		t.Fatalf("DecodeBody returned error: %v", err)
	}
	if ping.Echo != "hello" || ping.ServiceState != string(StateRunning) || ping.AuthorizedUserSID != "S-1-5-21-1" {
		t.Fatalf("ping response = %+v", ping)
	}
}

func TestServiceReportsUnenrolledStatus(t *testing.T) {
	service := newTestService(serviceTestOptions{AuthorizedUserSID: "S-1-5-21-1", Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), IdentityProvider: testIdentityProvider("S-1-5-21-1")})
	service.transition(StateRunning)
	request, err := ipc.NewRequest("req-1", ipc.OperationGetStatus, ipc.StatusRequest{})
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}
	response, err := service.HandleIPC(context.Background(), request)
	if err != nil {
		t.Fatalf("HandleIPC returned error: %v", err)
	}
	var status ipc.AgentStatus
	if err := ipc.DecodeBody(response.Body, &status); err != nil {
		t.Fatalf("DecodeBody returned error: %v", err)
	}
	if status.EnrollmentState != ipc.EnrollmentStateUnenrolled || status.KeyName != "ZTNA_DeviceKey" || status.EnrollmentNonce == "" || !status.KeyExists {
		t.Fatalf("status = %+v", status)
	}
}

func TestServiceAcceptsValidatedEnrollmentAccessToken(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	service := newTestService(serviceTestOptions{
		AuthorizedUserSID: "S-1-5-21-1",
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:             func() time.Time { return now },
		IdentityProvider:  testIdentityProviderWithDevice("S-1-5-21-1", "device-1"),
		EnrollmentValidator: fakeEnrollmentValidator{result: &enrollment.ValidationResult{
			DeviceID: "device-1",
			Nonce:    "nonce-1",
		}},
	})
	service.enrollment.Nonce = "nonce-1"
	request, err := ipc.NewRequest("req-1", ipc.OperationStartEnrollment, ipc.StartEnrollmentRequest{
		AccessToken:          "header.payload.signature",
		AccessTokenExpiresAt: now.Add(time.Hour),
		Nonce:                "nonce-1",
		DeviceID:             "device-1",
		UserSID:              "S-1-5-21-1",
		KeyName:              "ZTNA_DeviceKey",
		UserEmail:            "alice@example.com",
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
	var ack ipc.StartEnrollmentResponse
	if err := ipc.DecodeBody(response.Body, &ack); err != nil {
		t.Fatalf("DecodeBody returned error: %v", err)
	}
	if !ack.Accepted || ack.EnrollmentState != ipc.EnrollmentStatePending {
		t.Fatalf("ack = %+v", ack)
	}
}

func TestServiceAcceptsEnrollmentAccessTokenFromVerifiedPeerSID(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	service := newTestService(serviceTestOptions{
		AuthorizedUserSID: "S-1-5-21-1",
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:             func() time.Time { return now },
		IdentityProvider:  testIdentityProviderWithDevice("S-1-5-21-1", "device-1"),
		EnrollmentValidator: fakeEnrollmentValidator{result: &enrollment.ValidationResult{
			DeviceID: "device-1",
			Nonce:    "nonce-1",
		}},
	})
	service.enrollment.Nonce = "nonce-1"
	request, err := ipc.NewRequest("req-1", ipc.OperationStartEnrollment, ipc.StartEnrollmentRequest{
		AccessToken:          "header.payload.signature",
		AccessTokenExpiresAt: now.Add(time.Hour),
		Nonce:                "nonce-1",
		DeviceID:             "device-1",
		KeyName:              "ZTNA_DeviceKey",
		SentAt:               now,
	})
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}
	ctx := ipc.ContextWithPeerIdentity(context.Background(), ipc.PeerIdentity{UserSID: "S-1-5-21-1", Verified: true})
	response, err := service.HandleIPC(ctx, request)
	if err != nil {
		t.Fatalf("HandleIPC returned error: %v", err)
	}
	if !response.OK {
		t.Fatalf("response error = %+v", response.Error)
	}
	var ack ipc.StartEnrollmentResponse
	if err := ipc.DecodeBody(response.Body, &ack); err != nil {
		t.Fatalf("DecodeBody returned error: %v", err)
	}
	if !ack.Accepted || ack.ActiveUserSID != "S-1-5-21-1" {
		t.Fatalf("ack = %+v", ack)
	}
}

func TestServiceRunsEnrollmentRunnerAfterValidatedToken(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	runner := &fakeEnrollmentRunner{result: &enrollment.RunnerResult{EnrollmentID: "enroll-1", CertificateSHA256: "cert-sha"}}
	service := newTestService(serviceTestOptions{
		AuthorizedUserSID: "S-1-5-21-1",
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:             func() time.Time { return now },
		IdentityProvider:  testIdentityProviderWithDevice("S-1-5-21-1", "device-1"),
		EnrollmentRunner:  runner,
		EnrollmentValidator: fakeEnrollmentValidator{result: &enrollment.ValidationResult{
			DeviceID: "device-1",
			Nonce:    "nonce-1",
		}},
	})
	service.enrollment.Nonce = "nonce-1"
	request, err := ipc.NewRequest("req-1", ipc.OperationStartEnrollment, ipc.StartEnrollmentRequest{
		AccessToken:          "header.payload.signature",
		AccessTokenExpiresAt: now.Add(time.Hour),
		Nonce:                "nonce-1",
		DeviceID:             "device-1",
		UserSID:              "S-1-5-21-1",
		KeyName:              "ZTNA_DeviceKey",
		UserEmail:            "alice@example.com",
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
	var ack ipc.StartEnrollmentResponse
	if err := ipc.DecodeBody(response.Body, &ack); err != nil {
		t.Fatalf("DecodeBody returned error: %v", err)
	}
	if ack.EnrollmentState != ipc.EnrollmentStateEnrolled {
		t.Fatalf("ack = %+v", ack)
	}
	if runner.input.AccessToken != "header.payload.signature" || runner.input.KeyName != "ZTNA_DeviceKey" || runner.input.UserEmail != "alice@example.com" {
		t.Fatalf("runner input = %+v", runner.input)
	}
	status := service.status()
	if status.EnrollmentState != ipc.EnrollmentStateEnrolled || status.CertificateSHA256 != "cert-sha" {
		t.Fatalf("status = %+v", status)
	}
}

func TestServiceReturnsDevicePostureReport(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	service := newTestService(serviceTestOptions{
		AuthorizedUserSID: "S-1-5-21-1",
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:             func() time.Time { return now },
		IdentityProvider:  testIdentityProviderWithDevice("S-1-5-21-1", "device-1"),
		PostureCollector: fakePostureCollector{report: ipc.DevicePostureReport{
			DeviceID:    "device-1",
			Hostname:    "host-1",
			OS:          "Windows",
			CollectedAt: now,
			Checks: []ipc.DevicePostureCheck{{
				Name:        "Firewall",
				Status:      ipc.DevicePostureStatusCritical,
				Description: "Firewall is disabled",
			}},
		}},
	})
	request, err := ipc.NewRequest("req-1", ipc.OperationGetDevicePosture, ipc.DevicePostureRequest{})
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
	var report ipc.DevicePostureReport
	if err := ipc.DecodeBody(response.Body, &report); err != nil {
		t.Fatalf("DecodeBody returned error: %v", err)
	}
	if report.DeviceID != "device-1" || len(report.Checks) != 1 || report.Checks[0].Status != ipc.DevicePostureStatusCritical {
		t.Fatalf("report = %+v", report)
	}
	status := service.status()
	if status.DevicePostureStatus != "collected" || status.DevicePostureCheckCount != 1 || !status.DevicePostureCollectedAt.Equal(now) {
		t.Fatalf("status = %+v", status)
	}
}

func TestServiceAppliesCatalogPosturePolicy(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	service := newTestService(serviceTestOptions{
		AuthorizedUserSID: "S-1-5-21-1",
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:             func() time.Time { return now },
		IdentityProvider:  testIdentityProviderWithDevice("S-1-5-21-1", "device-1"),
		PostureCollector: fakePostureCollector{report: ipc.DevicePostureReport{
			DeviceID:    "device-1",
			Hostname:    "host-1",
			OS:          "Windows",
			CollectedAt: now,
			Checks: []ipc.DevicePostureCheck{{
				Name:        "Firewall",
				Status:      ipc.DevicePostureStatusWarning,
				Description: "Some firewall profiles are disabled",
			}},
		}},
	})
	service.catalog.PosturePolicy = catalog.PosturePolicy{
		RequiredChecks:      []string{"Firewall", "Disk Encryption"},
		RequiredCheckStatus: ipc.DevicePostureStatusGood,
	}

	request, err := ipc.NewRequest("req-1", ipc.OperationGetDevicePosture, ipc.DevicePostureRequest{})
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}
	response, err := service.HandleIPC(context.Background(), request)
	if err != nil {
		t.Fatalf("HandleIPC returned error: %v", err)
	}
	var report ipc.DevicePostureReport
	if err := ipc.DecodeBody(response.Body, &report); err != nil {
		t.Fatalf("DecodeBody returned error: %v", err)
	}
	firewall := findPostureCheck(report, "Firewall")
	if firewall == nil || firewall.Status != ipc.DevicePostureStatusCritical || firewall.Details["Observed Status"] != ipc.DevicePostureStatusWarning || firewall.Details["Expected Status"] != ipc.DevicePostureStatusGood || firewall.Details["Compliance"] != "Not compliant" {
		t.Fatalf("firewall check = %+v", firewall)
	}
	disk := findPostureCheck(report, "Disk Encryption")
	if disk == nil || disk.Status != ipc.DevicePostureStatusCritical || disk.Details["Observed Status"] != "missing" {
		t.Fatalf("disk check = %+v", disk)
	}
}

func TestServiceReturnsAgentDashboard(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	service := newTestService(serviceTestOptions{
		AuthorizedUserSID: "S-1-5-21-1",
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:             func() time.Time { return now },
		IdentityProvider:  testIdentityProviderWithDevice("S-1-5-21-1", "device-1"),
		PostureCollector:  fakePostureCollector{report: testPostureReport(now, ipc.DevicePostureStatusGood)},
	})
	service.transition(StateRunning)
	service.enrollment.State = ipc.EnrollmentStateEnrolled
	service.enrollment.DeviceID = "device-1"
	service.session.State = sessionStatusReady
	service.session.UserSID = "S-1-5-21-1"
	service.session.UserEmail = "alice@example.com"
	service.catalog.Status = catalogStatusReady
	service.catalog.LastSyncedAt = now
	service.catalog.Resources = []catalog.Resource{{FQDN: "admin.example.test", ResourceID: "res-1", Protocol: "tcp", Port: 443}}

	request, err := ipc.NewRequest("req-1", ipc.OperationGetDashboard, ipc.DashboardRequest{})
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
	var dashboard ipc.AgentDashboard
	if err := ipc.DecodeBody(response.Body, &dashboard); err != nil {
		t.Fatalf("DecodeBody returned error: %v", err)
	}
	if dashboard.Connection.State != "connected" || dashboard.User.Email != "alice@example.com" || len(dashboard.Resources) != 1 || len(dashboard.Posture.Checks) == 0 {
		t.Fatalf("dashboard = %+v", dashboard)
	}
}

func TestServiceReturnsCatalogResources(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	service := newTestService(serviceTestOptions{AuthorizedUserSID: "S-1-5-21-1", Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Clock: func() time.Time { return now }})
	service.catalog.Status = catalogStatusReady
	service.catalog.LastSyncedAt = now
	service.catalog.Resources = []catalog.Resource{{FQDN: "ssh.lab.local", ResourceID: "res-ssh", Protocol: "tcp", Port: 22}}

	request, err := ipc.NewRequest("req-1", ipc.OperationGetCatalogResources, ipc.CatalogResourcesRequest{})
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}
	response, err := service.HandleIPC(context.Background(), request)
	if err != nil {
		t.Fatalf("HandleIPC returned error: %v", err)
	}
	var resources ipc.CatalogResourcesResponse
	if err := ipc.DecodeBody(response.Body, &resources); err != nil {
		t.Fatalf("DecodeBody returned error: %v", err)
	}
	if len(resources.Resources) != 1 || resources.Resources[0].FQDN != "ssh.lab.local" || resources.Resources[0].Status != "available" {
		t.Fatalf("resources = %+v", resources)
	}
}

func TestServiceDoesNotReportPostureBeforeEnrollment(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	reporter := &fakePostureReporter{}
	service := newTestService(serviceTestOptions{
		AuthorizedUserSID: "S-1-5-21-1",
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:             func() time.Time { return now },
		IdentityProvider:  testIdentityProviderWithDevice("S-1-5-21-1", "device-1"),
		PostureCollector:  fakePostureCollector{report: testPostureReport(now, ipc.DevicePostureStatusGood)},
		PostureReporter:   reporter,
	})
	reported, err := service.reportPostureIfReady(context.Background(), "test")
	if err != nil {
		t.Fatalf("reportPostureIfReady returned error: %v", err)
	}
	if reported || len(reporter.reports) != 0 {
		t.Fatalf("reported=%t reports=%d", reported, len(reporter.reports))
	}
	status := service.status()
	if status.DevicePostureStatus != postureStatusWaitingForEnrollment {
		t.Fatalf("status = %+v", status)
	}
}

func TestServiceReportsPostureAfterEnrollment(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	reporter := &fakePostureReporter{}
	service := newTestService(serviceTestOptions{
		AuthorizedUserSID: "S-1-5-21-1",
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:             func() time.Time { return now },
		IdentityProvider:  testIdentityProviderWithDevice("S-1-5-21-1", "device-1"),
		PostureCollector:  fakePostureCollector{report: testPostureReport(now, ipc.DevicePostureStatusGood)},
		PostureReporter:   reporter,
	})
	service.enrollment.State = ipc.EnrollmentStateEnrolled
	reported, err := service.reportPostureIfReady(context.Background(), "test")
	if err != nil {
		t.Fatalf("reportPostureIfReady returned error: %v", err)
	}
	if !reported || len(reporter.reports) != 1 {
		t.Fatalf("reported=%t reports=%d", reported, len(reporter.reports))
	}
	status := service.status()
	if status.DevicePostureStatus != postureStatusReported || !status.DevicePostureReportedAt.Equal(now) || status.DevicePostureReportError != "" {
		t.Fatalf("status = %+v", status)
	}
}

func TestServiceReportsCriticalPostureTransition(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	reporter := &fakePostureReporter{}
	collector := &sequencePostureCollector{reports: []ipc.DevicePostureReport{
		testPostureReport(now, ipc.DevicePostureStatusCritical),
		testPostureReport(now.Add(time.Minute), ipc.DevicePostureStatusCritical),
	}}
	service := newTestService(serviceTestOptions{
		AuthorizedUserSID: "S-1-5-21-1",
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:             func() time.Time { return now },
		IdentityProvider:  testIdentityProviderWithDevice("S-1-5-21-1", "device-1"),
		PostureCollector:  collector,
		PostureReporter:   reporter,
	})
	service.enrollment.State = ipc.EnrollmentStateEnrolled
	service.posture.Report = testPostureReport(now.Add(-time.Minute), ipc.DevicePostureStatusGood)
	reported, err := service.reportCriticalPostureIfChanged(context.Background())
	if err != nil {
		t.Fatalf("reportCriticalPostureIfChanged returned error: %v", err)
	}
	if !reported || len(reporter.reports) != 1 {
		t.Fatalf("reported=%t reports=%d", reported, len(reporter.reports))
	}
	reported, err = service.reportCriticalPostureIfChanged(context.Background())
	if err != nil {
		t.Fatalf("second reportCriticalPostureIfChanged returned error: %v", err)
	}
	if reported || len(reporter.reports) != 1 {
		t.Fatalf("second reported=%t reports=%d", reported, len(reporter.reports))
	}
}

func TestServiceSendsHeartbeatAfterEnrollment(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	reporter := &fakeHeartbeatPostureReporter{}
	service := newTestService(serviceTestOptions{
		AuthorizedUserSID: "S-1-5-21-1",
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:             func() time.Time { return now },
		IdentityProvider:  testIdentityProviderWithDevice("S-1-5-21-1", "device-1"),
		PostureReporter:   reporter,
	})
	if err := service.sendHeartbeatIfReady(context.Background()); err != nil {
		t.Fatalf("sendHeartbeatIfReady before enrollment returned error: %v", err)
	}
	if len(reporter.heartbeats) != 0 {
		t.Fatalf("heartbeats before enrollment = %d", len(reporter.heartbeats))
	}
	service.enrollment.State = ipc.EnrollmentStateEnrolled
	if err := service.sendHeartbeatIfReady(context.Background()); err != nil {
		t.Fatalf("sendHeartbeatIfReady returned error: %v", err)
	}
	if len(reporter.heartbeats) != 1 || reporter.heartbeats[0] != "device-1" {
		t.Fatalf("heartbeats = %+v", reporter.heartbeats)
	}
}

func TestServiceSyncsCatalogAndAppliesDNSAfterEnrollment(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	catalogClient := &fakeCatalogClient{catalog: catalog.Catalog{Version: "v1", PolicyEpoch: "v1", DNSSuffixes: []string{"example.test"}, Resources: []catalog.Resource{{FQDN: "admin.example.test", ResourceID: "res-1", Protocol: "https", Port: 443}}, TTLSeconds: 300}}
	dnsConfigurator := &fakeDNSConfigurator{}
	service := newTestService(serviceTestOptions{
		AuthorizedUserSID: "S-1-5-21-1",
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:             func() time.Time { return now },
		IdentityProvider:  testIdentityProviderWithDevice("S-1-5-21-1", "device-1"),
		CatalogClient:     catalogClient,
		DNSConfigurator:   dnsConfigurator,
		DNSServer:         "127.0.0.1",
	})
	service.enrollment.State = ipc.EnrollmentStateEnrolled
	service.enrollment.DeviceID = "device-1"
	service.setAccessToken("user.access.token", now.Add(time.Hour), "S-1-5-21-1", "device-1", now)

	applied, err := service.syncDeviceCatalogIfReady(context.Background())
	if err != nil {
		t.Fatalf("syncDeviceCatalogIfReady returned error: %v", err)
	}
	if !applied {
		t.Fatalf("expected catalog to be applied")
	}
	if catalogClient.accessToken != "user.access.token" || catalogClient.currentVersion != "" {
		t.Fatalf("catalog client = %+v", catalogClient)
	}
	if len(dnsConfigurator.configs) != 1 {
		t.Fatalf("dns apply count = %d", len(dnsConfigurator.configs))
	}
	appliedConfig := dnsConfigurator.configs[0]
	if appliedConfig.DNSServer != "127.0.0.1" || !appliedConfig.HardenDoH || len(appliedConfig.DNSSuffixes) != 1 || appliedConfig.DNSSuffixes[0] != "example.test" {
		t.Fatalf("dns config = %+v", appliedConfig)
	}
	if status := service.status(); status.DevicePostureStatus != postureStatusUnknown || status.CatalogStatus != catalogStatusReady || status.CatalogVersion != "v1" || status.CatalogDNSSuffixCount != 1 || status.CatalogResourceCount != 1 || status.SyntheticDNSStatus != "ready" || status.SyntheticResourceCount != 1 {
		t.Fatalf("catalog sync leaked into status: %+v", status)
	}
}

func TestServiceUpdatesAccessTokenThroughIPC(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	service := newTestService(serviceTestOptions{
		AuthorizedUserSID: "S-1-5-21-1",
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:             func() time.Time { return now },
		IdentityProvider:  testIdentityProviderWithDevice("S-1-5-21-1", "device-1"),
	})
	service.enrollment.State = ipc.EnrollmentStateEnrolled
	service.enrollment.DeviceID = "device-1"
	request, err := ipc.NewRequest("req-1", ipc.OperationUpdateAccessToken, ipc.UpdateAccessTokenRequest{
		AccessToken: "user.access.token",
		ExpiresAt:   now.Add(time.Hour),
		DeviceID:    "device-1",
		UserSID:     "S-1-5-21-1",
		SentAt:      now,
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
	var ack ipc.UpdateAccessTokenResponse
	if err := ipc.DecodeBody(response.Body, &ack); err != nil {
		t.Fatalf("DecodeBody returned error: %v", err)
	}
	if !ack.Accepted || ack.DeviceID != "device-1" || !ack.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("ack = %+v", ack)
	}
	status := service.status()
	if status.SessionState != sessionStatusReady || !status.AccessTokenExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("status = %+v", status)
	}
}

func TestServiceRejectsAccessTokenForWrongSID(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	service := newTestService(serviceTestOptions{
		AuthorizedUserSID: "S-1-5-21-1",
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:             func() time.Time { return now },
		IdentityProvider:  testIdentityProviderWithDevice("S-1-5-21-1", "device-1"),
	})
	service.enrollment.State = ipc.EnrollmentStateEnrolled
	service.enrollment.DeviceID = "device-1"
	request, err := ipc.NewRequest("req-1", ipc.OperationUpdateAccessToken, ipc.UpdateAccessTokenRequest{
		AccessToken: "user.access.token",
		ExpiresAt:   now.Add(time.Hour),
		DeviceID:    "device-1",
		UserSID:     "S-1-5-21-2",
		SentAt:      now,
	})
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}
	response, err := service.HandleIPC(context.Background(), request)
	if err != nil {
		t.Fatalf("HandleIPC returned error: %v", err)
	}
	if response.OK || response.Error.Code != ipc.ErrorCodeInvalidRequest {
		t.Fatalf("response = %+v", response)
	}
	if status := service.status(); status.SessionState != sessionStatusRejected {
		t.Fatalf("status = %+v", status)
	}
}

func TestServiceRejectsAccessTokenWhenPeerSIDDoesNotMatchPayload(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	service := newTestService(serviceTestOptions{
		AuthorizedUserSID: "S-1-5-21-1",
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:             func() time.Time { return now },
		IdentityProvider:  testIdentityProviderWithDevice("S-1-5-21-1", "device-1"),
	})
	service.enrollment.State = ipc.EnrollmentStateEnrolled
	service.enrollment.DeviceID = "device-1"
	request, err := ipc.NewRequest("req-1", ipc.OperationUpdateAccessToken, ipc.UpdateAccessTokenRequest{
		AccessToken: "user.access.token",
		ExpiresAt:   now.Add(time.Hour),
		DeviceID:    "device-1",
		UserSID:     "S-1-5-21-1",
		SentAt:      now,
	})
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}
	ctx := ipc.ContextWithPeerIdentity(context.Background(), ipc.PeerIdentity{UserSID: "S-1-5-21-2", Verified: true})
	response, err := service.HandleIPC(ctx, request)
	if err != nil {
		t.Fatalf("HandleIPC returned error: %v", err)
	}
	if response.OK || response.Error.Code != ipc.ErrorCodeInvalidRequest {
		t.Fatalf("response = %+v", response)
	}
	if status := service.status(); status.SessionState != sessionStatusRejected {
		t.Fatalf("status = %+v", status)
	}
}

func TestServiceCatalogSyncRequiresAccessToken(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	catalogClient := &fakeCatalogClient{catalog: catalog.Catalog{Version: "v1", PolicyEpoch: "v1", DNSSuffixes: []string{"example.test"}, TTLSeconds: 300}}
	service := newTestService(serviceTestOptions{
		AuthorizedUserSID: "S-1-5-21-1",
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:             func() time.Time { return now },
		IdentityProvider:  testIdentityProviderWithDevice("S-1-5-21-1", "device-1"),
		CatalogClient:     catalogClient,
		DNSConfigurator:   &fakeDNSConfigurator{},
	})
	service.enrollment.State = ipc.EnrollmentStateEnrolled
	service.enrollment.DeviceID = "device-1"
	applied, err := service.syncDeviceCatalogIfReady(context.Background())
	if err != nil {
		t.Fatalf("syncDeviceCatalogIfReady returned error: %v", err)
	}
	if applied || catalogClient.accessToken != "" {
		t.Fatalf("applied=%t catalogClient=%+v", applied, catalogClient)
	}
	if status := service.status(); status.CatalogStatus != catalogStatusTokenRequired {
		t.Fatalf("status = %+v", status)
	}
}

func TestServiceConfiguresPAGRPCClient(t *testing.T) {
	service := newTestService(serviceTestOptions{
		AuthorizedUserSID: "S-1-5-21-1",
		PAURL:             "https://cloud.example",
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		IdentityProvider:  testIdentityProviderWithDevice("S-1-5-21-1", "device-1"),
	})
	if service.paClient == nil || service.postureReporter == nil || service.catalogClient == nil || service.enrollmentValidator == nil {
		t.Fatalf("PA gRPC client dependencies were not configured")
	}
}

func TestServiceRejectsEnrollmentAccessTokenWithoutValidator(t *testing.T) {
	service := newTestService(serviceTestOptions{AuthorizedUserSID: "S-1-5-21-1", Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), IdentityProvider: testIdentityProvider("S-1-5-21-1")})
	service.enrollment.Nonce = "nonce-1"
	now := time.Now().UTC()
	request, err := ipc.NewRequest("req-1", ipc.OperationStartEnrollment, ipc.StartEnrollmentRequest{
		AccessToken:          "header.payload.signature",
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
	if response.OK || response.Error.Code != ipc.ErrorCodeServiceUnavailable {
		t.Fatalf("response = %+v", response)
	}
}

func TestServiceRejectsEnrollmentAccessTokenWrongSID(t *testing.T) {
	service := newTestService(serviceTestOptions{
		AuthorizedUserSID:   "S-1-5-21-1",
		Logger:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		IdentityProvider:    testIdentityProvider("S-1-5-21-1"),
		EnrollmentValidator: fakeEnrollmentValidator{result: &enrollment.ValidationResult{}},
	})
	service.enrollment.Nonce = "nonce-1"
	now := time.Now().UTC()
	request, err := ipc.NewRequest("req-1", ipc.OperationStartEnrollment, ipc.StartEnrollmentRequest{
		AccessToken:          "header.payload.signature",
		AccessTokenExpiresAt: now.Add(time.Hour),
		Nonce:                "nonce-1",
		DeviceID:             "device-1",
		UserSID:              "S-1-5-21-2",
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
	if response.OK || response.Error.Code != ipc.ErrorCodeInvalidRequest {
		t.Fatalf("response = %+v", response)
	}
}

func TestServiceRejectsEnrollmentAccessTokenWhenPeerSIDDoesNotMatchPayload(t *testing.T) {
	service := newTestService(serviceTestOptions{
		AuthorizedUserSID:   "S-1-5-21-1",
		Logger:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		IdentityProvider:    testIdentityProvider("S-1-5-21-1"),
		EnrollmentValidator: fakeEnrollmentValidator{result: &enrollment.ValidationResult{}},
	})
	service.enrollment.Nonce = "nonce-1"
	now := time.Now().UTC()
	request, err := ipc.NewRequest("req-1", ipc.OperationStartEnrollment, ipc.StartEnrollmentRequest{
		AccessToken:          "header.payload.signature",
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
	ctx := ipc.ContextWithPeerIdentity(context.Background(), ipc.PeerIdentity{UserSID: "S-1-5-21-2", Verified: true})
	response, err := service.HandleIPC(ctx, request)
	if err != nil {
		t.Fatalf("HandleIPC returned error: %v", err)
	}
	if response.OK || response.Error.Code != ipc.ErrorCodeInvalidRequest {
		t.Fatalf("response = %+v", response)
	}
}

func TestServiceRejectsEnrollmentAccessTokenWrongServiceDeviceID(t *testing.T) {
	service := newTestService(serviceTestOptions{
		AuthorizedUserSID: "S-1-5-21-1",
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		IdentityProvider:  testIdentityProviderWithDevice("S-1-5-21-1", "device-from-ek"),
		EnrollmentValidator: fakeEnrollmentValidator{result: &enrollment.ValidationResult{
			DeviceID: "device-override",
			Nonce:    "nonce-1",
		}},
	})
	service.enrollment.Nonce = "nonce-1"
	now := time.Now().UTC()
	request, err := ipc.NewRequest("req-1", ipc.OperationStartEnrollment, ipc.StartEnrollmentRequest{
		AccessToken:          "header.payload.signature",
		AccessTokenExpiresAt: now.Add(time.Hour),
		Nonce:                "nonce-1",
		DeviceID:             "device-override",
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
	if response.OK || response.Error.Code != ipc.ErrorCodeInvalidRequest {
		t.Fatalf("response = %+v", response)
	}
}

type fakeEnrollmentRunner struct {
	input  enrollment.RunnerInput
	result *enrollment.RunnerResult
	err    error
}

type fakeEnrollmentRenewer struct {
	input  enrollment.RenewalInput
	result *enrollment.RunnerResult
	err    error
	calls  int
}

type fakePostureCollector struct {
	report ipc.DevicePostureReport
	err    error
}

func (collector fakePostureCollector) Collect(context.Context, string) (ipc.DevicePostureReport, error) {
	if collector.err != nil {
		return ipc.DevicePostureReport{}, collector.err
	}
	return collector.report, nil
}

type sequencePostureCollector struct {
	reports []ipc.DevicePostureReport
	index   int
}

func (collector *sequencePostureCollector) Collect(context.Context, string) (ipc.DevicePostureReport, error) {
	if len(collector.reports) == 0 {
		return ipc.DevicePostureReport{}, errors.New("no reports")
	}
	if collector.index >= len(collector.reports) {
		return collector.reports[len(collector.reports)-1], nil
	}
	report := collector.reports[collector.index]
	collector.index++
	return report, nil
}

type fakePostureReporter struct {
	reports []ipc.DevicePostureReport
	err     error
}

func (reporter *fakePostureReporter) ReportDevicePosture(_ context.Context, report ipc.DevicePostureReport) error {
	if reporter.err != nil {
		return reporter.err
	}
	reporter.reports = append(reporter.reports, report)
	return nil
}

type fakeHeartbeatPostureReporter struct {
	fakePostureReporter
	heartbeats []string
}

func (reporter *fakeHeartbeatPostureReporter) SendHeartbeat(_ context.Context, deviceID string) error {
	reporter.heartbeats = append(reporter.heartbeats, deviceID)
	return nil
}

type fakeCatalogClient struct {
	catalog        catalog.Catalog
	err            error
	accessToken    string
	currentVersion string
}

func (client *fakeCatalogClient) GetCatalog(_ context.Context, accessToken, currentVersion string) (catalog.Catalog, error) {
	client.accessToken = accessToken
	client.currentVersion = currentVersion
	if client.err != nil {
		return catalog.Catalog{}, client.err
	}
	return client.catalog, nil
}

type fakeDNSConfigurator struct {
	configs []dnscontrol.Config
	err     error
}

func (configurator *fakeDNSConfigurator) Apply(_ context.Context, config dnscontrol.Config) error {
	if configurator.err != nil {
		return configurator.err
	}
	configurator.configs = append(configurator.configs, config)
	return nil
}

func testPostureReport(collectedAt time.Time, firewallStatus string) ipc.DevicePostureReport {
	return ipc.DevicePostureReport{
		DeviceID:    "device-1",
		Hostname:    "host-1",
		OS:          "Windows",
		CollectedAt: collectedAt,
		Checks: []ipc.DevicePostureCheck{{
			Name:        "Firewall",
			Status:      firewallStatus,
			Description: "Firewall state",
		}},
	}
}

func findPostureCheck(report ipc.DevicePostureReport, name string) *ipc.DevicePostureCheck {
	for index := range report.Checks {
		if strings.EqualFold(report.Checks[index].Name, name) {
			return &report.Checks[index]
		}
	}
	return nil
}

func (runner *fakeEnrollmentRunner) Enroll(_ context.Context, input enrollment.RunnerInput) (*enrollment.RunnerResult, error) {
	runner.input = input
	if runner.err != nil {
		return nil, runner.err
	}
	return runner.result, nil
}

func (renewer *fakeEnrollmentRenewer) Renew(_ context.Context, input enrollment.RenewalInput) (*enrollment.RunnerResult, error) {
	renewer.calls++
	renewer.input = input
	if renewer.err != nil {
		return nil, renewer.err
	}
	return renewer.result, nil
}

type fakeEnrollmentValidator struct {
	result *enrollment.ValidationResult
	err    error
}

func (validator fakeEnrollmentValidator) ValidateEnrollmentAccessToken(context.Context, enrollment.ValidationInput) (*enrollment.ValidationResult, error) {
	if validator.err != nil {
		return nil, validator.err
	}
	if validator.result == nil {
		return nil, errors.New("no validation result")
	}
	return validator.result, nil
}

type fakeIdentityProvider struct {
	snapshot deviceidentity.Snapshot
	err      error
}

func (provider fakeIdentityProvider) Snapshot(context.Context) (deviceidentity.Snapshot, error) {
	return provider.snapshot, provider.err
}

func testIdentityProvider(userSID string) fakeIdentityProvider {
	return testIdentityProviderWithDevice(userSID, "")
}

func testIdentityProviderWithDevice(userSID, deviceID string) fakeIdentityProvider {
	return fakeIdentityProvider{snapshot: deviceidentity.Snapshot{
		DeviceID:       deviceID,
		DeviceIDSource: deviceidentity.DeviceIDSourceTPMEKPublicSHA256,
		ActiveUserSID:  userSID,
		KeyName:        deviceidentity.KeyNameForDevice(),
		KeyExists:      true,
		KeyProvider:    deviceidentity.MicrosoftPlatformCryptoProvider,
		CollectedAt:    time.Unix(1000, 0).UTC(),
	}}
}

func TestServiceRunsWithInjectedListener(t *testing.T) {
	listener := newPipeListener()
	service := newTestService(serviceTestOptions{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		ListenerFactory: func(string) (net.Listener, error) {
			return listener, nil
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	waitForState(t, service, StateRunning)

	client := ipc.NewClient(func(context.Context) (net.Conn, error) { return listener.Dial(), nil })
	var response ipc.PingResponse
	if err := client.Call(context.Background(), ipc.OperationPing, ipc.PingRequest{Message: "hello"}, &response); err != nil {
		t.Fatalf("Call returned error: %v", err)
	}
	if response.Echo != "hello" {
		t.Fatalf("response = %+v", response)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("service did not stop")
	}
}

func TestServiceStartsSyntheticDNSServerWithLifecycleContext(t *testing.T) {
	listener := newPipeListener()
	dnsServer := newFakeDNSResolverServer()
	service := newTestService(serviceTestOptions{
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		DNSResolverServer: dnsServer,
		ListenerFactory: func(string) (net.Listener, error) {
			return listener, nil
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	waitForState(t, service, StateRunning)

	select {
	case <-dnsServer.started:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatalf("synthetic DNS server was not started")
	}
	cancel()
	select {
	case <-dnsServer.stopped:
	case <-time.After(2 * time.Second):
		t.Fatalf("synthetic DNS server did not receive cancellation")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("service did not stop")
	}
}

func TestServiceStartsNetworkManagerWithLifecycleContext(t *testing.T) {
	listener := newPipeListener()
	networkManager := newFakeNetworkManager()
	service := newTestService(serviceTestOptions{
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		NetworkManager: networkManager,
		ListenerFactory: func(string) (net.Listener, error) {
			return listener, nil
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	waitForState(t, service, StateRunning)

	select {
	case <-networkManager.started:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatalf("network manager was not started")
	}
	status := service.status()
	if status.NetworkStatus != agentnetwork.StatusReady || status.TUNName != "ZTNA-Test" || status.TUNRouteCIDR != "100.64.0.0/10" {
		cancel()
		t.Fatalf("status = %+v", status)
	}
	cancel()
	select {
	case <-networkManager.stopped:
	case <-time.After(2 * time.Second):
		t.Fatalf("network manager did not receive cancellation")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("service did not stop")
	}
}

func waitForState(t *testing.T, service *Service, expected State) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline:
			t.Fatalf("state = %q, want %q", service.State(), expected)
		case <-ticker.C:
			if service.State() == expected {
				return
			}
		}
	}
}

type pipeListener struct {
	connections chan net.Conn
	closed      chan struct{}
}

func newPipeListener() *pipeListener {
	return &pipeListener{connections: make(chan net.Conn), closed: make(chan struct{})}
}

func (listener *pipeListener) Accept() (net.Conn, error) {
	select {
	case connection := <-listener.connections:
		return connection, nil
	case <-listener.closed:
		return nil, net.ErrClosed
	}
}

func (listener *pipeListener) Close() error {
	select {
	case <-listener.closed:
	default:
		close(listener.closed)
	}
	return nil
}

func (listener *pipeListener) Addr() net.Addr { return pipeAddr("pipe") }

func (listener *pipeListener) Dial() net.Conn {
	serverConn, clientConn := net.Pipe()
	listener.connections <- serverConn
	return clientConn
}

type pipeAddr string

func (addr pipeAddr) Network() string { return string(addr) }
func (addr pipeAddr) String() string  { return string(addr) }

type fakeDNSResolverServer struct {
	started chan struct{}
	stopped chan struct{}
	once    sync.Once
}

func newFakeDNSResolverServer() *fakeDNSResolverServer {
	return &fakeDNSResolverServer{started: make(chan struct{}), stopped: make(chan struct{})}
}

func (server *fakeDNSResolverServer) Run(ctx context.Context) error {
	server.once.Do(func() { close(server.started) })
	<-ctx.Done()
	close(server.stopped)
	return nil
}

type fakeNetworkManager struct {
	started chan struct{}
	stopped chan struct{}
	once    sync.Once
}

func newFakeNetworkManager() *fakeNetworkManager {
	return &fakeNetworkManager{started: make(chan struct{}), stopped: make(chan struct{})}
}

func (manager *fakeNetworkManager) Run(ctx context.Context) error {
	manager.once.Do(func() { close(manager.started) })
	<-ctx.Done()
	close(manager.stopped)
	return nil
}

func (manager *fakeNetworkManager) Status() agentnetwork.Status {
	return agentnetwork.Status{State: agentnetwork.StatusReady, TUNName: "ZTNA-Test", TUNIP: "100.64.0.1", TUNNetmask: "255.192.0.0", CGNATRange: "100.64.0.0/10"}
}
