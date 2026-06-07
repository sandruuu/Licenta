package service

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"agent/internal/service/enrollment"
	flowauthorization "agent/internal/service/flow-authorization"
	gatewaytunnel "agent/internal/service/gateway-tunnel"
	trafficinterception "agent/internal/service/traffic-interception"
	"agent/internal/service/usersession"
)

func TestResourceStreamConnectorAuthorizesAndOpensGatewayStream(t *testing.T) {
	sessionProvider := &fakeAuthenticatedSessionProvider{
		session: usersession.AuthenticatedSession{
			AgentSessionID:    "agent-session",
			AgentSessionToken: "agent-token",
			ExpiresAt:         time.Now().Add(time.Hour),
		},
		found: true,
	}
	enrollmentProvider := &fakeEnrollmentRecordProvider{record: enrollment.EnrollmentRecord{
		DeviceID:             "device-1",
		DeviceCertThumbprint: "thumbprint",
		GatewayEndpoints:     []string{"gateway-fallback.example.test:9443"},
	}}
	authorizer := &fakeFlowAuthorizer{response: flowauthorization.AuthorizeResponse{
		Decision:          flowauthorization.DecisionAllow,
		SessionID:         "sess-1",
		SessionToken:      "session-token",
		GatewayID:         "gw-1",
		GatewayEndpoint:   "gateway.example.test:9443",
		GatewayServerName: "gateway.example.test",
		ResourceID:        "res-web",
		Protocol:          "https",
		Port:              443,
	}}
	tunnel := &fakeGatewayTunnel{}
	connector := &resourceStreamConnector{
		enrollment:   enrollmentProvider,
		userSessions: sessionProvider,
		authorizer:   authorizer,
		tunnel:       tunnel,
	}

	stream, err := connector.OpenResourceStream(context.Background(), trafficinterception.StreamRequest{
		ResourceID:  "res-web",
		FQDN:        "wapp.com",
		Protocol:    "https",
		Port:        443,
		SyntheticIP: "100.64.0.3",
		Process: &trafficinterception.ProcessIdentity{
			PID:    42,
			Name:   "browser.exe",
			Path:   `C:\Program Files\Browser\browser.exe`,
			SHA256: "abcdef",
			Signer: "CN=Browser",
		},
	})
	if err != nil {
		t.Fatalf("OpenResourceStream returned error: %v", err)
	}
	_ = stream.Close()

	if authorizer.request.AgentSessionToken != "agent-token" || authorizer.request.ResourceID != "res-web" || authorizer.request.Protocol != "https" || authorizer.request.Port != 443 {
		t.Fatalf("authorization request = %+v", authorizer.request)
	}
	if authorizer.request.Process == nil || authorizer.request.Process.PID != 42 || authorizer.request.Process.Name != "browser.exe" || authorizer.request.Process.SHA256 != "abcdef" {
		t.Fatalf("authorization process = %+v", authorizer.request.Process)
	}
	if tunnel.request.SessionID != "sess-1" || tunnel.request.SessionToken != "session-token" || tunnel.request.GatewayEndpoint != "gateway.example.test:9443" || tunnel.request.GatewayServerName != "gateway.example.test" || tunnel.request.TargetHost != "100.64.0.3" || tunnel.request.Protocol != "https" {
		t.Fatalf("gateway request = %+v", tunnel.request)
	}
	if tunnel.request.Process == nil || tunnel.request.Process.PID != 42 || tunnel.request.Process.Name != "browser.exe" || tunnel.request.Process.SHA256 != "abcdef" {
		t.Fatalf("gateway process = %+v", tunnel.request.Process)
	}
}

func TestResourceStreamConnectorRecordsStepUpRequired(t *testing.T) {
	var stepUpRequest trafficinterception.StreamRequest
	var stepUpAuthorization flowauthorization.AuthorizeResponse
	connector := &resourceStreamConnector{
		enrollment: &fakeEnrollmentRecordProvider{record: enrollment.EnrollmentRecord{DeviceID: "device-1"}},
		userSessions: &fakeAuthenticatedSessionProvider{
			session: usersession.AuthenticatedSession{AgentSessionToken: "agent-token"},
			found:   true,
		},
		authorizer: &fakeFlowAuthorizer{response: flowauthorization.AuthorizeResponse{
			Decision:          flowauthorization.DecisionStepUpRequired,
			Reason:            "step-up required",
			StepUpChallengeID: "stepup-1",
			StepUpURL:         "https://pdp.example.test/browser/step-up/stepup-1",
		}},
		tunnel: &fakeGatewayTunnel{},
		onStepUpRequired: func(request trafficinterception.StreamRequest, authorization flowauthorization.AuthorizeResponse) {
			stepUpRequest = request
			stepUpAuthorization = authorization
		},
	}

	_, err := connector.OpenResourceStream(context.Background(), trafficinterception.StreamRequest{ResourceID: "res-web", Protocol: "tcp", Port: 443, SyntheticIP: "100.64.0.3"})
	if !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("OpenResourceStream error = %v, want ErrStepUpRequired", err)
	}
	if connector.tunnel.(*fakeGatewayTunnel).opened {
		t.Fatalf("gateway stream was opened for step-up decision")
	}
	if stepUpRequest.ResourceID != "res-web" || stepUpAuthorization.StepUpURL == "" {
		t.Fatalf("step-up callback request=%+v authorization=%+v", stepUpRequest, stepUpAuthorization)
	}
}

func TestResourceStreamConnectorRecordsResourceDenied(t *testing.T) {
	var deniedRequest trafficinterception.StreamRequest
	var deniedAuthorization flowauthorization.AuthorizeResponse
	var deniedErr error
	connector := &resourceStreamConnector{
		enrollment: &fakeEnrollmentRecordProvider{record: enrollment.EnrollmentRecord{DeviceID: "device-1"}},
		userSessions: &fakeAuthenticatedSessionProvider{
			session: usersession.AuthenticatedSession{AgentSessionToken: "agent-token"},
			found:   true,
		},
		authorizer: &fakeFlowAuthorizer{response: flowauthorization.AuthorizeResponse{
			Decision: flowauthorization.DecisionDeny,
			Reason:   "verification rejected",
		}},
		tunnel: &fakeGatewayTunnel{},
		onResourceDenied: func(request trafficinterception.StreamRequest, authorization flowauthorization.AuthorizeResponse, err error) {
			deniedRequest = request
			deniedAuthorization = authorization
			deniedErr = err
		},
	}

	_, err := connector.OpenResourceStream(context.Background(), trafficinterception.StreamRequest{
		ResourceID: "res-rdp",
		FQDN:       "rdp-desktop.trustcloud.test",
		Protocol:   "tcp",
		Port:       3389,
	})
	if err == nil {
		t.Fatal("OpenResourceStream returned nil error")
	}
	if deniedRequest.ResourceID != "res-rdp" || deniedRequest.FQDN != "rdp-desktop.trustcloud.test" {
		t.Fatalf("denied request = %+v", deniedRequest)
	}
	if deniedAuthorization.Reason != "verification rejected" || deniedErr == nil {
		t.Fatalf("denied authorization=%+v err=%v", deniedAuthorization, deniedErr)
	}
}

func TestResourceStreamConnectorRequiresAuthenticatedSession(t *testing.T) {
	var authRequiredRequest trafficinterception.StreamRequest
	connector := &resourceStreamConnector{
		userSessions: &fakeAuthenticatedSessionProvider{},
		onAuthenticationRequired: func(request trafficinterception.StreamRequest) {
			authRequiredRequest = request
		},
	}
	_, err := connector.OpenResourceStream(context.Background(), trafficinterception.StreamRequest{ResourceID: "res-web", FQDN: "web.internal.example"})
	if !errors.Is(err, ErrAuthenticationRequired) {
		t.Fatalf("OpenResourceStream error = %v, want ErrAuthenticationRequired", err)
	}
	if authRequiredRequest.ResourceID != "res-web" || authRequiredRequest.FQDN != "web.internal.example" {
		t.Fatalf("auth required request = %+v", authRequiredRequest)
	}
}

func TestResourceStreamConnectorReusesCachedResourceSession(t *testing.T) {
	sessionProvider := &fakeAuthenticatedSessionProvider{
		session: usersession.AuthenticatedSession{
			AgentSessionID:    "agent-session",
			AgentSessionToken: "agent-token",
			ExpiresAt:         time.Now().Add(time.Hour),
		},
		found: true,
	}
	authorizer := &fakeFlowAuthorizer{response: flowauthorization.AuthorizeResponse{
		Decision:          flowauthorization.DecisionAllow,
		SessionID:         "sess-1",
		SessionToken:      "session-token",
		GatewayID:         "gw-1",
		GatewayEndpoint:   "gateway.example.test:9443",
		GatewayServerName: "gateway.example.test",
		ResourceID:        "res-web",
		Protocol:          "https",
		Port:              443,
		ExpiresAt:         time.Now().Add(5 * time.Minute),
	}}
	tunnel := &fakeGatewayTunnel{}
	connector := &resourceStreamConnector{
		enrollment: &fakeEnrollmentRecordProvider{record: enrollment.EnrollmentRecord{
			DeviceID:             "device-1",
			DeviceCertThumbprint: "thumbprint",
		}},
		userSessions: sessionProvider,
		authorizer:   authorizer,
		tunnel:       tunnel,
	}

	for i := 0; i < 2; i++ {
		stream, err := connector.OpenResourceStream(context.Background(), trafficinterception.StreamRequest{
			ResourceID:  "res-web",
			FQDN:        "wapp.com",
			Protocol:    "https",
			Port:        443,
			SyntheticIP: "100.64.0.3",
		})
		if err != nil {
			t.Fatalf("OpenResourceStream(%d) returned error: %v", i, err)
		}
		_ = stream.Close()
	}
	if authorizer.count != 1 {
		t.Fatalf("AuthorizeResource count = %d, want 1", authorizer.count)
	}
}

func TestResourceStreamConnectorSharesRenewalForSameProvisionedSession(t *testing.T) {
	sessionProvider := &fakeAuthenticatedSessionProvider{
		session: usersession.AuthenticatedSession{
			AgentSessionID:    "agent-session",
			AgentSessionToken: "agent-token",
			ExpiresAt:         time.Now().Add(time.Hour),
		},
		found: true,
	}
	authorizer := &fakeFlowAuthorizer{response: flowauthorization.AuthorizeResponse{
		Decision:          flowauthorization.DecisionAllow,
		SessionID:         "sess-1",
		SessionToken:      "session-token",
		GatewayID:         "gw-1",
		GatewayEndpoint:   "gateway.example.test:9443",
		GatewayServerName: "gateway.example.test",
		ResourceID:        "res-web",
		Protocol:          "https",
		Port:              443,
		ExpiresAt:         time.Now().Add(5 * time.Minute),
	}}
	connector := &resourceStreamConnector{
		enrollment: &fakeEnrollmentRecordProvider{record: enrollment.EnrollmentRecord{
			DeviceID:             "device-1",
			DeviceCertThumbprint: "thumbprint",
		}},
		userSessions: sessionProvider,
		authorizer:   authorizer,
		tunnel:       &fakeGatewayTunnel{},
	}

	first, err := connector.OpenResourceStream(context.Background(), trafficinterception.StreamRequest{
		ResourceID:  "res-web",
		FQDN:        "wapp.com",
		Protocol:    "https",
		Port:        443,
		SyntheticIP: "100.64.0.3",
		Process:     &trafficinterception.ProcessIdentity{PID: 101, Name: "browser.exe", SHA256: "hash-one"},
	})
	if err != nil {
		t.Fatalf("first OpenResourceStream returned error: %v", err)
	}
	second, err := connector.OpenResourceStream(context.Background(), trafficinterception.StreamRequest{
		ResourceID:  "res-web",
		FQDN:        "wapp.com",
		Protocol:    "https",
		Port:        443,
		SyntheticIP: "100.64.0.3",
		Process:     &trafficinterception.ProcessIdentity{PID: 202, Name: "browser-helper.exe", SHA256: "hash-two"},
	})
	if err != nil {
		t.Fatalf("second OpenResourceStream returned error: %v", err)
	}

	if authorizer.count != 2 {
		t.Fatalf("AuthorizeResource count = %d, want 2 for distinct process cache keys", authorizer.count)
	}
	if count, refs := connector.activeRenewalStats(); count != 1 || refs != 2 {
		t.Fatalf("active renewal stats = count:%d refs:%d, want count:1 refs:2", count, refs)
	}
	_ = first.Close()
	if count, refs := connector.activeRenewalStats(); count != 1 || refs != 1 {
		t.Fatalf("active renewal stats after first close = count:%d refs:%d, want count:1 refs:1", count, refs)
	}
	_ = second.Close()
	if count, refs := connector.activeRenewalStats(); count != 0 || refs != 0 {
		t.Fatalf("active renewal stats after second close = count:%d refs:%d, want count:0 refs:0", count, refs)
	}
}

func TestResourceStreamConnectorDoesNotReuseCachedSessionAcrossProcesses(t *testing.T) {
	sessionProvider := &fakeAuthenticatedSessionProvider{
		session: usersession.AuthenticatedSession{
			AgentSessionID:    "agent-session",
			AgentSessionToken: "agent-token",
			ExpiresAt:         time.Now().Add(time.Hour),
		},
		found: true,
	}
	authorizer := &fakeFlowAuthorizer{response: flowauthorization.AuthorizeResponse{
		Decision:          flowauthorization.DecisionAllow,
		SessionID:         "sess-1",
		SessionToken:      "session-token",
		GatewayID:         "gw-1",
		GatewayEndpoint:   "gateway.example.test:9443",
		GatewayServerName: "gateway.example.test",
		ResourceID:        "res-web",
		Protocol:          "https",
		Port:              443,
		ExpiresAt:         time.Now().Add(5 * time.Minute),
	}}
	connector := &resourceStreamConnector{
		enrollment: &fakeEnrollmentRecordProvider{record: enrollment.EnrollmentRecord{
			DeviceID:             "device-1",
			DeviceCertThumbprint: "thumbprint",
		}},
		userSessions: sessionProvider,
		authorizer:   authorizer,
		tunnel:       &fakeGatewayTunnel{},
	}

	requests := []trafficinterception.StreamRequest{
		{
			ResourceID: "res-web",
			FQDN:       "wapp.com",
			Protocol:   "https",
			Port:       443,
			Process:    &trafficinterception.ProcessIdentity{PID: 101, Name: "allowed.exe", SHA256: "hash-one"},
		},
		{
			ResourceID: "res-web",
			FQDN:       "wapp.com",
			Protocol:   "https",
			Port:       443,
			Process:    &trafficinterception.ProcessIdentity{PID: 202, Name: "other.exe", SHA256: "hash-two"},
		},
	}
	for i, request := range requests {
		stream, err := connector.OpenResourceStream(context.Background(), request)
		if err != nil {
			t.Fatalf("OpenResourceStream(%d) returned error: %v", i, err)
		}
		_ = stream.Close()
	}
	if authorizer.count != 2 {
		t.Fatalf("AuthorizeResource count = %d, want 2 for distinct process identities", authorizer.count)
	}
}

func TestResourceStreamConnectorDropsCachedSessionAfterGatewayRejectsIt(t *testing.T) {
	sessionProvider := &fakeAuthenticatedSessionProvider{
		session: usersession.AuthenticatedSession{
			AgentSessionID:    "agent-session",
			AgentSessionToken: "agent-token",
			ExpiresAt:         time.Now().Add(time.Hour),
		},
		found: true,
	}
	authorizer := &fakeFlowAuthorizer{response: flowauthorization.AuthorizeResponse{
		Decision:          flowauthorization.DecisionAllow,
		SessionID:         "sess-1",
		SessionToken:      "session-token",
		GatewayID:         "gw-1",
		GatewayEndpoint:   "gateway.example.test:9443",
		GatewayServerName: "gateway.example.test",
		ResourceID:        "res-web",
		Protocol:          "https",
		Port:              443,
		ExpiresAt:         time.Now().Add(5 * time.Minute),
	}}
	tunnel := &fakeGatewayTunnel{}
	connector := &resourceStreamConnector{
		enrollment: &fakeEnrollmentRecordProvider{record: enrollment.EnrollmentRecord{
			DeviceID:             "device-1",
			DeviceCertThumbprint: "thumbprint",
		}},
		userSessions: sessionProvider,
		authorizer:   authorizer,
		tunnel:       tunnel,
	}

	stream, err := connector.OpenResourceStream(context.Background(), trafficinterception.StreamRequest{
		ResourceID:  "res-web",
		FQDN:        "wapp.com",
		Protocol:    "https",
		Port:        443,
		SyntheticIP: "100.64.0.3",
	})
	if err != nil {
		t.Fatalf("first OpenResourceStream returned error: %v", err)
	}
	_ = stream.Close()

	tunnel.err = &gatewaytunnel.GatewayError{Code: gatewaytunnel.CodeSessionInvalid, Message: "session no longer exists"}
	_, err = connector.OpenResourceStream(context.Background(), trafficinterception.StreamRequest{
		ResourceID:  "res-web",
		FQDN:        "wapp.com",
		Protocol:    "https",
		Port:        443,
		SyntheticIP: "100.64.0.3",
	})
	if err == nil {
		t.Fatal("second OpenResourceStream returned nil error")
	}
	if authorizer.count != 2 {
		t.Fatalf("AuthorizeResource count = %d, want reauthorization after stale Gateway session", authorizer.count)
	}
}

type fakeAuthenticatedSessionProvider struct {
	session usersession.AuthenticatedSession
	found   bool
	err     error
}

func (provider *fakeAuthenticatedSessionProvider) ActiveAuthenticatedSession() (usersession.AuthenticatedSession, bool, error) {
	if provider.err != nil {
		return usersession.AuthenticatedSession{}, false, provider.err
	}
	return provider.session, provider.found, nil
}

type fakeEnrollmentRecordProvider struct {
	record enrollment.EnrollmentRecord
	err    error
}

func (provider *fakeEnrollmentRecordProvider) Record(context.Context) (enrollment.EnrollmentRecord, error) {
	if provider.err != nil {
		return enrollment.EnrollmentRecord{}, provider.err
	}
	return provider.record, nil
}

type fakeFlowAuthorizer struct {
	request  flowauthorization.AuthorizeRequest
	response flowauthorization.AuthorizeResponse
	err      error
	closed   bool
	count    int
}

func (authorizer *fakeFlowAuthorizer) AuthorizeResource(_ context.Context, request flowauthorization.AuthorizeRequest) (flowauthorization.AuthorizeResponse, error) {
	authorizer.count++
	authorizer.request = request
	if authorizer.err != nil {
		return flowauthorization.AuthorizeResponse{}, authorizer.err
	}
	return authorizer.response, nil
}

func (authorizer *fakeFlowAuthorizer) Close() error {
	authorizer.closed = true
	return nil
}

type fakeGatewayTunnel struct {
	request gatewaytunnel.ResourceStreamRequest
	err     error
	opened  bool
}

func (tunnel *fakeGatewayTunnel) OpenResourceStream(_ context.Context, request gatewaytunnel.ResourceStreamRequest) (net.Conn, error) {
	tunnel.request = request
	if tunnel.err != nil {
		return nil, tunnel.err
	}
	left, right := net.Pipe()
	_ = right.Close()
	tunnel.opened = true
	return left, nil
}

func (tunnel *fakeGatewayTunnel) Status() gatewaytunnel.Status {
	if tunnel.err != nil {
		return gatewaytunnel.Status{State: gatewaytunnel.StatusError, LastError: tunnel.err.Error()}
	}
	return gatewaytunnel.Status{State: gatewaytunnel.StatusReady}
}

func (connector *resourceStreamConnector) activeRenewalStats() (int, int) {
	connector.mu.Lock()
	defer connector.mu.Unlock()
	count := len(connector.resourceSessionRenewals)
	refs := 0
	for _, renewal := range connector.resourceSessionRenewals {
		if renewal != nil {
			refs += renewal.refs
		}
	}
	return count, refs
}
