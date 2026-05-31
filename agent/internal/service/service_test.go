package service

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"agent/internal/service/enrollment"
	trafficinterception "agent/internal/service/traffic-interception"
	"agent/internal/service/usersession"
	"agent/internal/shared/ipc"
)

type serviceTestOptions struct {
	Logger                      *slog.Logger
	ListenerFactory             func() (net.Listener, error)
	DeviceDataCollector         DeviceDataCollector
	DeviceDataSyncClientFactory DeviceDataSyncClientFactory
	ProtectedResources          ProtectedResourcesManager
	Clock                       func() time.Time
}

func newTestService(options serviceTestOptions) *Service {
	return New(Config{}, Dependencies{
		Logger:                      options.Logger,
		ListenerFactory:             options.ListenerFactory,
		DeviceDataCollector:         options.DeviceDataCollector,
		DeviceDataSyncClientFactory: options.DeviceDataSyncClientFactory,
		ProtectedResources:          options.ProtectedResources,
		Clock:                       options.Clock,
	})
}

func TestServiceHandlesPing(t *testing.T) {
	service := newTestService(serviceTestOptions{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
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
	if ping.Echo != "hello" || ping.ServiceState != string(StateRunning) {
		t.Fatalf("ping response = %+v", ping)
	}
}

func TestServiceReportsUnenrolledStatus(t *testing.T) {
	service := newTestService(serviceTestOptions{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
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
	if status.EnrollmentState != ipc.EnrollmentStateUnenrolled || status.DeviceDataStatus != statusDisabled {
		t.Fatalf("status = %+v", status)
	}
}

func TestServiceReturnsAgentDashboard(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	service := newTestService(serviceTestOptions{
		Logger:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:               func() time.Time { return now },
		DeviceDataCollector: fakeDeviceDataCollector{report: testDeviceDataReport(now, ipc.DeviceDataStatusGood)},
	})
	service.transition(StateRunning)

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
	if dashboard.Connection.State != "unenrolled" || dashboard.Enrollment.State != ipc.EnrollmentStateUnenrolled || len(dashboard.DeviceData.Checks) != 0 || len(dashboard.Catalog.Resources) != 0 {
		t.Fatalf("dashboard = %+v", dashboard)
	}
}

func TestServiceStartsInteractiveEnrollmentAndCompletesInBackground(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	store := &memoryEnrollmentStore{}
	client := &fakeEnrollmentClient{
		start: enrollment.EnrollmentStartSessionResponse{
			EnrollmentSessionID: "erq_123",
			AuthURL:             "https://pdp.example.com/browser/enroll/erq_123",
			DeviceChallenge:     "device-challenge",
			PollSecret:          "poll-secret",
			ExpiresAt:           now.Add(time.Minute),
			PollInterval:        10 * time.Millisecond,
		},
		statuses: []enrollment.EnrollmentSessionStatusResponse{{Status: enrollment.StatusReadyForDeviceProof}},
		complete: enrollment.EnrollmentCompleteSessionResponse{
			DeviceID:              "dev_123",
			IDPProfileID:          "entra_acme",
			CertificatePEM:        testCertificatePEM,
			CertificateThumbprint: "thumbprint",
			ExpiresAt:             now.Add(time.Hour),
			PDPEndpoint:           "https://pdp.example.com",
			GatewayEndpoints:      []string{"gw1.example.com"},
		},
	}
	service := New(Config{EnrollmentPollInterval: 10 * time.Millisecond, EnrollmentTimeout: time.Minute}, Dependencies{
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:            func() time.Time { return now },
		EnrollmentClient: client,
		DeviceIdentity: fakeDeviceIdentity{
			csr: enrollment.EnrollmentCSR{
				KeyName:     "TrustAgentDeviceKey",
				Provider:    "test-provider",
				CSRPEM:      "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----",
				CSRHash:     "csr-hash",
				SPKIHash:    "spki-hash",
				DeviceNonce: "device-nonce",
			},
		},
		EnrollmentStore: store,
	})

	request, err := ipc.NewRequest("req-1", ipc.OperationStartEnrollmentInteractive, ipc.StartEnrollmentInteractiveRequest{})
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
	var start ipc.StartEnrollmentInteractiveResponse
	if err := ipc.DecodeBody(response.Body, &start); err != nil {
		t.Fatalf("DecodeBody returned error: %v", err)
	}
	if !start.Started || start.AuthURL != client.start.AuthURL || start.State != ipc.EnrollmentStateEnrolling {
		t.Fatalf("start = %+v", start)
	}
	waitForEnrollmentState(t, service, ipc.EnrollmentStateEnrolled)
	if store.saved.DeviceID != "dev_123" || store.saved.EnrolledByIDPProfileID != "entra_acme" {
		t.Fatalf("saved enrollment = %+v", store.saved)
	}
}

func TestServiceDoesNotStartInteractiveEnrollmentWhenAlreadyEnrolled(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	store := &memoryEnrollmentStore{saved: enrollment.EnrollmentRecord{
		EnrollmentState:      ipc.EnrollmentStateEnrolled,
		DeviceID:             "dev_existing",
		DeviceKeyName:        "TrustAgentDeviceKey",
		DeviceCertThumbprint: "thumbprint",
		CertificateExpiry:    now.Add(time.Hour),
	}}
	client := &fakeEnrollmentClient{
		start: enrollment.EnrollmentStartSessionResponse{
			EnrollmentSessionID: "erq_new",
			AuthURL:             "https://pdp.example.com/browser/enroll/erq_new",
			DeviceChallenge:     "device-challenge",
			PollSecret:          "poll-secret",
			ExpiresAt:           now.Add(time.Minute),
		},
	}
	service := New(Config{EnrollmentPollInterval: 10 * time.Millisecond, EnrollmentTimeout: time.Minute}, Dependencies{
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:            func() time.Time { return now },
		EnrollmentClient: client,
		DeviceIdentity:   fakeDeviceIdentity{},
		EnrollmentStore:  store,
	})

	request, err := ipc.NewRequest("req-1", ipc.OperationStartEnrollmentInteractive, ipc.StartEnrollmentInteractiveRequest{})
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
	var start ipc.StartEnrollmentInteractiveResponse
	if err := ipc.DecodeBody(response.Body, &start); err != nil {
		t.Fatalf("DecodeBody returned error: %v", err)
	}
	if start.Started || start.AuthURL != "" || start.State != ipc.EnrollmentStateEnrolled {
		t.Fatalf("start = %+v", start)
	}
	if client.startCalls != 0 {
		t.Fatalf("StartSession calls = %d, want 0", client.startCalls)
	}
	snapshot := service.enrollment.Snapshot()
	if snapshot.State != ipc.EnrollmentStateEnrolled || snapshot.DeviceID != "dev_existing" {
		t.Fatalf("enrollment snapshot = %+v", snapshot)
	}
}

func TestServiceReportsDeviceDataImmediatelyAfterEnrollment(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	store := &memoryEnrollmentStore{}
	deviceDataSyncClient := &fakeDeviceDataSyncClient{}
	client := &fakeEnrollmentClient{
		start: enrollment.EnrollmentStartSessionResponse{
			EnrollmentSessionID: "erq_123",
			AuthURL:             "https://pdp.example.com/browser/enroll/erq_123",
			DeviceChallenge:     "device-challenge",
			PollSecret:          "poll-secret",
			ExpiresAt:           now.Add(time.Minute),
			PollInterval:        10 * time.Millisecond,
		},
		statuses: []enrollment.EnrollmentSessionStatusResponse{{Status: enrollment.StatusReadyForDeviceProof}},
		complete: enrollment.EnrollmentCompleteSessionResponse{
			DeviceID:              "dev_123",
			CertificatePEM:        testCertificatePEM,
			CertificateThumbprint: "thumbprint",
			ExpiresAt:             now.Add(time.Hour),
		},
	}
	service := New(Config{
		EnrollmentPollInterval:           10 * time.Millisecond,
		EnrollmentTimeout:                time.Minute,
		DeviceDataSyncInterval:           30 * time.Minute,
		DeviceDataSyncChangeScanInterval: time.Hour,
	}, Dependencies{
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:            func() time.Time { return now },
		EnrollmentClient: client,
		DeviceIdentity: fakeDeviceIdentity{
			csr: enrollment.EnrollmentCSR{
				KeyName:     "TrustAgentDeviceKey",
				Provider:    "test-provider",
				CSRPEM:      "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----",
				CSRHash:     "csr-hash",
				SPKIHash:    "spki-hash",
				DeviceNonce: "device-nonce",
			},
		},
		EnrollmentStore:     store,
		DeviceDataCollector: fakeDeviceDataCollector{report: testDeviceDataReport(now, ipc.DeviceDataStatusGood)},
		DeviceDataSyncClientFactory: func(context.Context, enrollment.EnrollmentRecord) (DeviceDataSyncClient, error) {
			return deviceDataSyncClient, nil
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go service.runDeviceDataSync(ctx)

	request, err := ipc.NewRequest("req-1", ipc.OperationStartEnrollmentInteractive, ipc.StartEnrollmentInteractiveRequest{})
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}
	if response, err := service.HandleIPC(context.Background(), request); err != nil || !response.OK {
		t.Fatalf("HandleIPC response=%+v err=%v", response, err)
	}
	waitForEnrollmentState(t, service, ipc.EnrollmentStateEnrolled)
	report := deviceDataSyncClient.waitForReports(t, 1)[0]
	if report.DeviceID != "dev_123" || len(report.Checks) != 1 {
		t.Fatalf("device data sync report = %+v", report)
	}
}

func TestServiceReportsDeviceDataWhenChecksChange(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	store := &memoryEnrollmentStore{saved: enrollment.EnrollmentRecord{
		EnrollmentState:      ipc.EnrollmentStateEnrolled,
		DeviceID:             "dev_123",
		DeviceKeyName:        "TrustAgentDeviceKey",
		DeviceCertThumbprint: "cert-thumb",
		CertificateExpiry:    now.Add(time.Hour),
	}}
	deviceDataSyncClient := &fakeDeviceDataSyncClient{}
	collector := &sequenceDeviceDataCollector{reports: []ipc.DeviceDataReport{
		testDeviceDataReport(now, ipc.DeviceDataStatusGood),
		testDeviceDataReport(now, ipc.DeviceDataStatusCritical),
	}}
	service := New(Config{
		DeviceDataSyncInterval:           30 * time.Minute,
		DeviceDataSyncChangeScanInterval: 10 * time.Millisecond,
	}, Dependencies{
		Logger:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:               func() time.Time { return now },
		EnrollmentStore:     store,
		DeviceIdentity:      fakeDeviceIdentity{},
		DeviceDataCollector: collector,
		DeviceDataSyncClientFactory: func(context.Context, enrollment.EnrollmentRecord) (DeviceDataSyncClient, error) {
			return deviceDataSyncClient, nil
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go service.runDeviceDataSync(ctx)

	reports := deviceDataSyncClient.waitForReports(t, 2)
	if reports[0].Checks[0].Status != ipc.DeviceDataStatusGood || reports[1].Checks[0].Status != ipc.DeviceDataStatusCritical {
		t.Fatalf("device data sync reports = %+v", reports)
	}
}

func TestServiceReportsDeviceDataImmediatelyOnDeviceDataSyncTrigger(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	store := &memoryEnrollmentStore{saved: enrollment.EnrollmentRecord{
		EnrollmentState:      ipc.EnrollmentStateEnrolled,
		DeviceID:             "dev_123",
		DeviceKeyName:        "TrustAgentDeviceKey",
		DeviceCertThumbprint: "cert-thumb",
		CertificateExpiry:    now.Add(time.Hour),
	}}
	deviceDataSyncClient := &fakeDeviceDataSyncClient{}
	collector := &sequenceDeviceDataCollector{reports: []ipc.DeviceDataReport{
		testDeviceDataReport(now, ipc.DeviceDataStatusGood),
		testDeviceDataReport(now, ipc.DeviceDataStatusCritical),
	}}
	service := New(Config{
		DeviceDataSyncInterval:           30 * time.Minute,
		DeviceDataSyncChangeScanInterval: time.Hour,
	}, Dependencies{
		Logger:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:               func() time.Time { return now },
		EnrollmentStore:     store,
		DeviceIdentity:      fakeDeviceIdentity{},
		DeviceDataCollector: collector,
		DeviceDataSyncClientFactory: func(context.Context, enrollment.EnrollmentRecord) (DeviceDataSyncClient, error) {
			return deviceDataSyncClient, nil
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go service.runDeviceDataSync(ctx)

	first := deviceDataSyncClient.waitForReports(t, 1)
	if first[0].Checks[0].Status != ipc.DeviceDataStatusGood {
		t.Fatalf("first device data sync report = %+v", first[0])
	}
	service.deviceDataSync.Trigger("firewall_policy")
	reports := deviceDataSyncClient.waitForReports(t, 2)
	if reports[1].Checks[0].Status != ipc.DeviceDataStatusCritical {
		t.Fatalf("device data sync reports = %+v", reports)
	}
}

func TestServiceStartsUserLoginAndLoadsCatalog(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	store := &memoryEnrollmentStore{saved: enrollment.EnrollmentRecord{
		EnrollmentState:      ipc.EnrollmentStateEnrolled,
		DeviceID:             "dev_123",
		DeviceKeyName:        "TrustAgentDeviceKey",
		DeviceCertThumbprint: "cert-thumb",
		CertificateExpiry:    now.Add(time.Hour),
	}}
	sessionClient := &fakeUserSessionClient{
		start: usersession.StartSessionResponse{
			SessionRequestID: "srq_123",
			AuthURL:          "https://pdp.example.com/browser/session/srq_123",
			ClaimSecret:      "claim-secret",
			ExpiresAt:        now.Add(time.Minute),
			PollInterval:     10 * time.Millisecond,
			Status:           usersession.StatusWaitingForUserLogin,
		},
		statuses: []usersession.SessionStatusResponse{{Status: usersession.StatusReadyToClaim}},
		claim: usersession.ClaimSessionResponse{
			AgentSessionID:    "sess_123",
			AgentSessionToken: "session-token",
			ExpiresAt:         now.Add(time.Minute),
			DisplayName:       "user@example.com",
			Email:             "user@example.com",
		},
		catalog: usersession.CatalogResponse{
			Version: "cat_1",
			Resources: []ipc.CatalogResource{{
				ResourceID:  "res_crm",
				DisplayName: "CRM",
				FQDN:        "crm.internal.example",
				Protocol:    "https",
				Port:        443,
			}},
			TTLSeconds:  300,
			PolicyEpoch: "1",
		},
	}
	protectedResources := &fakeProtectedResources{}
	service := New(Config{LoginPollInterval: 10 * time.Millisecond, LoginTimeout: time.Minute}, Dependencies{
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:              func() time.Time { return now },
		EnrollmentStore:    store,
		UserSessionClient:  sessionClient,
		ProtectedResources: protectedResources,
		DeviceIdentity:     fakeDeviceIdentity{},
	})
	peerCtx := ipc.ContextWithPeerIdentity(context.Background(), ipc.PeerIdentity{
		UserSID:               "S-1-5-21-1000",
		WindowsLogonSessionID: "00000000:000003e7",
		WindowsSessionID:      "1",
		Verified:              true,
	})
	request, err := ipc.NewRequest("req-1", ipc.OperationStartUserLoginInteractive, ipc.StartUserLoginInteractiveRequest{})
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}
	response, err := service.HandleIPC(peerCtx, request)
	if err != nil {
		t.Fatalf("HandleIPC returned error: %v", err)
	}
	if !response.OK {
		t.Fatalf("response error = %+v", response.Error)
	}
	var start ipc.StartUserLoginInteractiveResponse
	if err := ipc.DecodeBody(response.Body, &start); err != nil {
		t.Fatalf("DecodeBody returned error: %v", err)
	}
	if !start.Started || start.AuthURL != sessionClient.start.AuthURL {
		t.Fatalf("start = %+v", start)
	}
	waitForUserSessionState(t, service, peerCtx, ipc.UserSessionStateAuthenticated)
	dashboard := service.dashboard(peerCtx)
	if dashboard.UserSession.Email != "user@example.com" || len(dashboard.Catalog.Resources) != 1 {
		t.Fatalf("dashboard user session = %+v catalog=%+v", dashboard.UserSession, dashboard.Catalog)
	}
	applied := protectedResources.lastApplied()
	if applied.Version != "cat_1" || len(applied.Resources) != 1 {
		t.Fatalf("protected resources catalog = %+v", applied)
	}
}

func TestServicePausesAndRestoresProtectedResourcesOnLocalPostureChange(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	store := &memoryEnrollmentStore{saved: enrollment.EnrollmentRecord{
		EnrollmentState:      ipc.EnrollmentStateEnrolled,
		DeviceID:             "dev_123",
		DeviceKeyName:        "TrustAgentDeviceKey",
		DeviceCertThumbprint: "cert-thumb",
		CertificateExpiry:    now.Add(time.Hour),
	}}
	sessionClient := &fakeUserSessionClient{
		start: usersession.StartSessionResponse{
			SessionRequestID: "srq_123",
			AuthURL:          "https://pdp.example.com/browser/session/srq_123",
			ClaimSecret:      "claim-secret",
			ExpiresAt:        now.Add(time.Minute),
			PollInterval:     10 * time.Millisecond,
		},
		statuses: []usersession.SessionStatusResponse{{Status: usersession.StatusReadyToClaim}},
		claim: usersession.ClaimSessionResponse{
			AgentSessionID:    "sess_123",
			AgentSessionToken: "session-token",
			ExpiresAt:         now.Add(time.Minute),
			DisplayName:       "user@example.com",
			Email:             "user@example.com",
		},
		catalog: usersession.CatalogResponse{
			Version: "cat_1",
			Resources: []ipc.CatalogResource{{
				ResourceID: "res_ssh",
				FQDN:       "ssh.internal.example",
				Protocol:   "ssh",
				Port:       22,
			}},
			TTLSeconds:  300,
			PolicyEpoch: "1",
			DeviceDataPolicy: ipc.DeviceDataPolicy{
				RequiredChecks:      []string{"Firewall"},
				RequiredCheckStatus: ipc.DeviceDataStatusGood,
			},
		},
	}
	protectedResources := &fakeProtectedResources{}
	collector := &sequenceDeviceDataCollector{reports: []ipc.DeviceDataReport{
		testDeviceDataReport(now, ipc.DeviceDataStatusGood),
		testDeviceDataReport(now.Add(time.Second), ipc.DeviceDataStatusCritical),
		testDeviceDataReport(now.Add(time.Second), ipc.DeviceDataStatusGood),
	}}
	service := New(Config{LoginPollInterval: 10 * time.Millisecond, LoginTimeout: time.Minute}, Dependencies{
		Logger:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:               func() time.Time { return now },
		EnrollmentStore:     store,
		UserSessionClient:   sessionClient,
		ProtectedResources:  protectedResources,
		DeviceIdentity:      fakeDeviceIdentity{},
		DeviceDataCollector: collector,
	})
	peerCtx := ipc.ContextWithPeerIdentity(context.Background(), ipc.PeerIdentity{
		UserSID:               "S-1-5-21-1000",
		WindowsLogonSessionID: "00000000:000003e7",
		WindowsSessionID:      "1",
		Verified:              true,
	})
	request, err := ipc.NewRequest("req-1", ipc.OperationStartUserLoginInteractive, ipc.StartUserLoginInteractiveRequest{})
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}
	if response, err := service.HandleIPC(peerCtx, request); err != nil || !response.OK {
		t.Fatalf("HandleIPC response=%+v err=%v", response, err)
	}
	waitForUserSessionState(t, service, peerCtx, ipc.UserSessionStateAuthenticated)
	if len(protectedResources.appliedCatalogs()) != 1 {
		t.Fatalf("initial protected resource applies = %+v", protectedResources.appliedCatalogs())
	}

	if _, err := service.collectDeviceData(context.Background(), "dev_123"); err != nil {
		t.Fatalf("collect critical device data returned error: %v", err)
	}
	if protectedResources.clearCount() != 1 {
		t.Fatalf("protected resources clear count = %d, want 1", protectedResources.clearCount())
	}
	if dashboard := service.dashboard(peerCtx); !strings.Contains(dashboard.UserSession.Message, "paused") {
		t.Fatalf("dashboard message after posture failure = %+v", dashboard.UserSession)
	}

	if _, err := service.collectDeviceData(context.Background(), "dev_123"); err != nil {
		t.Fatalf("collect recovered device data returned error: %v", err)
	}
	if applied := protectedResources.appliedCatalogs(); len(applied) != 2 || applied[1].Version != "cat_1" {
		t.Fatalf("protected resources were not restored with catalog: %+v", applied)
	}
	if dashboard := service.dashboard(peerCtx); !strings.Contains(dashboard.UserSession.Message, "restored") {
		t.Fatalf("dashboard message after posture recovery = %+v", dashboard.UserSession)
	}
}

func TestServiceLogoutRevokesSessionAndClearsCatalog(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	store := &memoryEnrollmentStore{saved: enrollment.EnrollmentRecord{
		EnrollmentState:      ipc.EnrollmentStateEnrolled,
		DeviceID:             "dev_123",
		DeviceKeyName:        "TrustAgentDeviceKey",
		DeviceCertThumbprint: "cert-thumb",
		CertificateExpiry:    now.Add(time.Hour),
	}}
	sessionClient := &fakeUserSessionClient{
		start: usersession.StartSessionResponse{
			SessionRequestID: "srq_123",
			AuthURL:          "https://pdp.example.com/browser/session/srq_123",
			ClaimSecret:      "claim-secret",
			ExpiresAt:        now.Add(time.Minute),
			PollInterval:     10 * time.Millisecond,
			Status:           usersession.StatusWaitingForUserLogin,
		},
		statuses: []usersession.SessionStatusResponse{{Status: usersession.StatusReadyToClaim}},
		claim: usersession.ClaimSessionResponse{
			AgentSessionID:    "sess_123",
			AgentSessionToken: "session-token",
			ExpiresAt:         now.Add(time.Minute),
			DisplayName:       "user@example.com",
			Email:             "user@example.com",
		},
		catalog: usersession.CatalogResponse{
			Version: "cat_1",
			Resources: []ipc.CatalogResource{{
				ResourceID: "res_crm",
				FQDN:       "crm.internal.example",
				Protocol:   "https",
				Port:       443,
			}},
			TTLSeconds:  300,
			PolicyEpoch: "1",
		},
	}
	protectedResources := &fakeProtectedResources{}
	service := New(Config{LoginPollInterval: 10 * time.Millisecond, LoginTimeout: time.Minute}, Dependencies{
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:              func() time.Time { return now },
		EnrollmentStore:    store,
		UserSessionClient:  sessionClient,
		ProtectedResources: protectedResources,
		DeviceIdentity:     fakeDeviceIdentity{},
	})
	peerCtx := ipc.ContextWithPeerIdentity(context.Background(), ipc.PeerIdentity{
		UserSID:               "S-1-5-21-1000",
		WindowsLogonSessionID: "00000000:000003e7",
		WindowsSessionID:      "1",
		Verified:              true,
	})
	startRequest, err := ipc.NewRequest("req-start", ipc.OperationStartUserLoginInteractive, ipc.StartUserLoginInteractiveRequest{})
	if err != nil {
		t.Fatalf("NewRequest start returned error: %v", err)
	}
	if response, err := service.HandleIPC(peerCtx, startRequest); err != nil || !response.OK {
		t.Fatalf("start response = %+v err=%v", response, err)
	}
	waitForUserSessionState(t, service, peerCtx, ipc.UserSessionStateAuthenticated)
	if dashboard := service.dashboard(peerCtx); len(dashboard.Catalog.Resources) != 1 {
		t.Fatalf("catalog was not loaded before logout: %+v", dashboard.Catalog)
	}

	logoutRequest, err := ipc.NewRequest("req-logout", ipc.OperationLogoutUserSession, ipc.LogoutUserSessionRequest{})
	if err != nil {
		t.Fatalf("NewRequest logout returned error: %v", err)
	}
	response, err := service.HandleIPC(peerCtx, logoutRequest)
	if err != nil {
		t.Fatalf("logout HandleIPC returned error: %v", err)
	}
	if !response.OK {
		t.Fatalf("logout response error = %+v", response.Error)
	}
	var logout ipc.LogoutUserSessionResponse
	if err := ipc.DecodeBody(response.Body, &logout); err != nil {
		t.Fatalf("DecodeBody logout returned error: %v", err)
	}
	if !logout.LoggedOut || logout.State != ipc.UserSessionStateSignedOut {
		t.Fatalf("logout = %+v", logout)
	}
	if revokes := sessionClient.revokeRequests(); len(revokes) != 1 || revokes[0].AgentSessionToken != "session-token" || revokes[0].SessionID != "sess_123" {
		t.Fatalf("revoke requests = %+v", revokes)
	}
	if dashboard := service.dashboard(peerCtx); dashboard.UserSession.State != ipc.UserSessionStateSignedOut || len(dashboard.Catalog.Resources) != 0 {
		t.Fatalf("dashboard after logout user session = %+v catalog=%+v", dashboard.UserSession, dashboard.Catalog)
	}
	if protectedResources.clearCount() != 1 {
		t.Fatalf("protected resources clear count = %d, want 1", protectedResources.clearCount())
	}
}

func TestServiceDashboardPromptsSignInWhenEnrolledAndSignedOut(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	store := &memoryEnrollmentStore{saved: enrollment.EnrollmentRecord{
		EnrollmentState:      ipc.EnrollmentStateEnrolled,
		DeviceID:             "dev_123",
		DeviceKeyName:        "TrustAgentDeviceKey",
		DeviceCertThumbprint: "cert-thumb",
		CertificateExpiry:    now.Add(time.Hour),
	}}
	service := New(Config{}, Dependencies{
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:           func() time.Time { return now },
		EnrollmentStore: store,
		DeviceIdentity:  fakeDeviceIdentity{},
	})
	service.enrollment.Refresh(context.Background())
	peerCtx := ipc.ContextWithPeerIdentity(context.Background(), ipc.PeerIdentity{
		UserSID:               "S-1-5-21-1000",
		WindowsLogonSessionID: "00000000:000003e7",
		WindowsSessionID:      "1",
		Verified:              true,
	})

	dashboard := service.dashboard(peerCtx)
	if dashboard.UserSession.State != ipc.UserSessionStateSignedOut || !strings.Contains(dashboard.UserSession.Message, "Sign in required") || len(dashboard.Catalog.Resources) != 0 {
		t.Fatalf("signed-out dashboard = %+v catalog=%+v", dashboard.UserSession, dashboard.Catalog)
	}

	service.recordAuthenticationRequired(trafficinterception.StreamRequest{ResourceID: "res_crm", FQDN: "crm.internal.example"})
	dashboard = service.dashboard(peerCtx)
	if !strings.Contains(dashboard.UserSession.Message, "crm.internal.example") {
		t.Fatalf("dashboard did not include access prompt target: %+v", dashboard.UserSession)
	}
}

func waitForUserSessionState(t *testing.T, service *Service, ctx context.Context, expected string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline:
			t.Fatalf("user session state = %q, want %q", service.dashboard(ctx).UserSession.State, expected)
		case <-ticker.C:
			if service.dashboard(ctx).UserSession.State == expected {
				return
			}
		}
	}
}

func TestServiceRunsWithInjectedListener(t *testing.T) {
	listener := newPipeListener()
	service := newTestService(serviceTestOptions{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		ListenerFactory: func() (net.Listener, error) {
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

type fakeDeviceDataCollector struct {
	report ipc.DeviceDataReport
	err    error
}

func (collector fakeDeviceDataCollector) Collect(_ context.Context, deviceID string) (ipc.DeviceDataReport, error) {
	if collector.err != nil {
		return ipc.DeviceDataReport{}, collector.err
	}
	report := collector.report
	if report.DeviceID == "" {
		report.DeviceID = deviceID
	}
	return report, nil
}

type sequenceDeviceDataCollector struct {
	mu      sync.Mutex
	reports []ipc.DeviceDataReport
	index   int
}

func (collector *sequenceDeviceDataCollector) Collect(_ context.Context, deviceID string) (ipc.DeviceDataReport, error) {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	index := collector.index
	if index >= len(collector.reports) {
		index = len(collector.reports) - 1
	}
	report := collector.reports[index]
	if collector.index < len(collector.reports)-1 {
		collector.index++
	}
	if report.DeviceID == "" {
		report.DeviceID = deviceID
	}
	return report, nil
}

func testDeviceDataReport(collectedAt time.Time, firewallStatus string) ipc.DeviceDataReport {
	return ipc.DeviceDataReport{
		DeviceID:    "device-1",
		Hostname:    "host-1",
		OS:          "Windows",
		CollectedAt: collectedAt,
		Checks: []ipc.DeviceDataCheck{{
			Name:        "Firewall",
			Status:      firewallStatus,
			Description: "Firewall state",
		}},
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

func waitForEnrollmentState(t *testing.T, service *Service, expected ipc.EnrollmentState) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline:
			t.Fatalf("enrollment state = %q, want %q", service.status().EnrollmentState, expected)
		case <-ticker.C:
			if service.status().EnrollmentState == expected {
				return
			}
		}
	}
}

type fakeEnrollmentClient struct {
	start      enrollment.EnrollmentStartSessionResponse
	startCalls int
	statuses   []enrollment.EnrollmentSessionStatusResponse
	complete   enrollment.EnrollmentCompleteSessionResponse
}

func (client *fakeEnrollmentClient) StartSession(context.Context, enrollment.EnrollmentStartSessionRequest) (enrollment.EnrollmentStartSessionResponse, error) {
	client.startCalls++
	return client.start, nil
}

func (client *fakeEnrollmentClient) SessionStatus(context.Context, enrollment.EnrollmentSessionStatusRequest) (enrollment.EnrollmentSessionStatusResponse, error) {
	if len(client.statuses) == 0 {
		return enrollment.EnrollmentSessionStatusResponse{Status: enrollment.StatusWaitingForUserLogin}, nil
	}
	next := client.statuses[0]
	client.statuses = client.statuses[1:]
	return next, nil
}

func (client *fakeEnrollmentClient) CompleteSession(context.Context, enrollment.EnrollmentCompleteSessionRequest) (enrollment.EnrollmentCompleteSessionResponse, error) {
	return client.complete, nil
}

func (client *fakeEnrollmentClient) Close() error { return nil }

type fakeUserSessionClient struct {
	mu       sync.Mutex
	start    usersession.StartSessionResponse
	statuses []usersession.SessionStatusResponse
	claim    usersession.ClaimSessionResponse
	catalog  usersession.CatalogResponse
	revokes  []usersession.RevokeSessionRequest
}

func (client *fakeUserSessionClient) StartSession(context.Context, usersession.StartSessionRequest) (usersession.StartSessionResponse, error) {
	return client.start, nil
}

func (client *fakeUserSessionClient) SessionStatus(context.Context, usersession.SessionStatusRequest) (usersession.SessionStatusResponse, error) {
	if len(client.statuses) == 0 {
		return usersession.SessionStatusResponse{Status: usersession.StatusWaitingForUserLogin}, nil
	}
	next := client.statuses[0]
	client.statuses = client.statuses[1:]
	return next, nil
}

func (client *fakeUserSessionClient) ClaimSession(context.Context, usersession.ClaimSessionRequest) (usersession.ClaimSessionResponse, error) {
	return client.claim, nil
}

func (client *fakeUserSessionClient) GetCatalog(context.Context, usersession.GetCatalogRequest) (usersession.CatalogResponse, error) {
	return client.catalog, nil
}

func (client *fakeUserSessionClient) RevokeSession(_ context.Context, request usersession.RevokeSessionRequest) error {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.revokes = append(client.revokes, request)
	return nil
}

func (client *fakeUserSessionClient) Close() error { return nil }

func (client *fakeUserSessionClient) revokeRequests() []usersession.RevokeSessionRequest {
	client.mu.Lock()
	defer client.mu.Unlock()
	return append([]usersession.RevokeSessionRequest(nil), client.revokes...)
}

type fakeProtectedResources struct {
	mu      sync.Mutex
	applied []ipc.CatalogInfo
	cleared int
	err     error
}

func (manager *fakeProtectedResources) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

func (manager *fakeProtectedResources) ApplyCatalog(_ context.Context, catalog ipc.CatalogInfo) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.err != nil {
		return manager.err
	}
	manager.applied = append(manager.applied, catalog)
	return nil
}

func (manager *fakeProtectedResources) Clear(_ context.Context) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.err != nil {
		return manager.err
	}
	manager.cleared++
	return nil
}

func (manager *fakeProtectedResources) lastApplied() ipc.CatalogInfo {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.applied) == 0 {
		return ipc.CatalogInfo{}
	}
	return manager.applied[len(manager.applied)-1]
}

func (manager *fakeProtectedResources) appliedCatalogs() []ipc.CatalogInfo {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return append([]ipc.CatalogInfo(nil), manager.applied...)
}

func (manager *fakeProtectedResources) clearCount() int {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.cleared
}

type fakeDeviceDataSyncClient struct {
	mu      sync.Mutex
	reports []ipc.DeviceDataReport
	closed  bool
}

func (client *fakeDeviceDataSyncClient) ReportDeviceData(_ context.Context, report ipc.DeviceDataReport) error {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.reports = append(client.reports, cloneDeviceDataReport(report))
	return nil
}

func (client *fakeDeviceDataSyncClient) Close() error {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.closed = true
	return nil
}

func (client *fakeDeviceDataSyncClient) waitForReports(t *testing.T, count int) []ipc.DeviceDataReport {
	t.Helper()
	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline:
			client.mu.Lock()
			reports := append([]ipc.DeviceDataReport(nil), client.reports...)
			client.mu.Unlock()
			t.Fatalf("device data sync reports = %d, want %d: %+v", len(reports), count, reports)
		case <-ticker.C:
			client.mu.Lock()
			if len(client.reports) >= count {
				reports := make([]ipc.DeviceDataReport, len(client.reports))
				copy(reports, client.reports)
				client.mu.Unlock()
				return reports
			}
			client.mu.Unlock()
		}
	}
}

type fakeDeviceIdentity struct {
	csr enrollment.EnrollmentCSR
}

func (identity fakeDeviceIdentity) CreateEnrollmentCSR(context.Context, string) (enrollment.EnrollmentCSR, error) {
	return identity.csr, nil
}

func (identity fakeDeviceIdentity) SignEnrollmentProof(context.Context, string, []byte) ([]byte, error) {
	return []byte("signature"), nil
}

func (identity fakeDeviceIdentity) InstallDeviceCertificate(context.Context, enrollment.InstallCertificateRequest) (enrollment.InstalledCertificate, error) {
	return enrollment.InstalledCertificate{Thumbprint: "thumbprint", ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (identity fakeDeviceIdentity) CheckLocalEnrollment(context.Context, enrollment.EnrollmentRecord) (enrollment.LocalEnrollmentCheck, error) {
	return enrollment.LocalEnrollmentCheck{Enrolled: true}, nil
}

func (identity fakeDeviceIdentity) ClientCertificate(context.Context, enrollment.EnrollmentRecord) (tls.Certificate, func(), error) {
	return tls.Certificate{}, func() {}, nil
}

type memoryEnrollmentStore struct {
	saved enrollment.EnrollmentRecord
}

func (store *memoryEnrollmentStore) Load(context.Context) (enrollment.EnrollmentRecord, error) {
	if store.saved.EnrollmentState == "" {
		return enrollment.EnrollmentRecord{EnrollmentState: ipc.EnrollmentStateUnenrolled}, nil
	}
	return store.saved, nil
}

func (store *memoryEnrollmentStore) Save(_ context.Context, record enrollment.EnrollmentRecord) error {
	store.saved = record
	return nil
}

const testCertificatePEM = `-----BEGIN CERTIFICATE-----
MIIB
-----END CERTIFICATE-----`

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
