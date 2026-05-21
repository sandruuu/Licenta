package service

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"agent/internal/service/enrollment"
	"agent/internal/service/usersession"
	"agent/internal/shared/ipc"
)

type serviceTestOptions struct {
	Logger           *slog.Logger
	ListenerFactory  func() (net.Listener, error)
	PostureCollector DevicePostureCollector
	Clock            func() time.Time
}

func newTestService(options serviceTestOptions) *Service {
	return New(Config{}, Dependencies{
		Logger:           options.Logger,
		ListenerFactory:  options.ListenerFactory,
		PostureCollector: options.PostureCollector,
		Clock:            options.Clock,
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
	if status.EnrollmentState != ipc.EnrollmentStateUnenrolled || status.DevicePostureStatus != statusDisabled {
		t.Fatalf("status = %+v", status)
	}
}

func TestServiceReturnsDevicePostureReport(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	service := newTestService(serviceTestOptions{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:  func() time.Time { return now },
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
	if status.DevicePostureStatus != postureStatusCollected || status.DevicePostureCheckCount != 1 || !status.DevicePostureCollectedAt.Equal(now) {
		t.Fatalf("status = %+v", status)
	}
}

func TestServiceReturnsAgentDashboard(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	service := newTestService(serviceTestOptions{
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:            func() time.Time { return now },
		PostureCollector: fakePostureCollector{report: testPostureReport(now, ipc.DevicePostureStatusGood)},
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
	if dashboard.Connection.State != "unenrolled" || dashboard.Enrollment.State != ipc.EnrollmentStateUnenrolled || len(dashboard.Posture.Checks) == 0 {
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
				FQDN:        "crm.internal",
				Protocol:    "https",
				Port:        443,
			}},
			TTLSeconds:  300,
			PolicyEpoch: "1",
		},
	}
	service := New(Config{LoginPollInterval: 10 * time.Millisecond, LoginTimeout: time.Minute}, Dependencies{
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:             func() time.Time { return now },
		EnrollmentStore:   store,
		UserSessionClient: sessionClient,
		DeviceIdentity:    fakeDeviceIdentity{},
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
	start    enrollment.EnrollmentStartSessionResponse
	statuses []enrollment.EnrollmentSessionStatusResponse
	complete enrollment.EnrollmentCompleteSessionResponse
}

func (client *fakeEnrollmentClient) StartSession(context.Context, enrollment.EnrollmentStartSessionRequest) (enrollment.EnrollmentStartSessionResponse, error) {
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
	start    usersession.StartSessionResponse
	statuses []usersession.SessionStatusResponse
	claim    usersession.ClaimSessionResponse
	catalog  usersession.CatalogResponse
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

func (client *fakeUserSessionClient) RevokeSession(context.Context, usersession.RevokeSessionRequest) error {
	return nil
}

func (client *fakeUserSessionClient) Close() error { return nil }

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
