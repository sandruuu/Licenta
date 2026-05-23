package service

import (
	"context"
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
		Decision:        flowauthorization.DecisionAllow,
		SessionID:       "sess-1",
		SessionToken:    "session-token",
		GatewayID:       "gw-1",
		GatewayEndpoint: "gateway.example.test:9443",
		ResourceID:      "res-web",
		Protocol:        "tcp",
		Port:            443,
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
	})
	if err != nil {
		t.Fatalf("OpenResourceStream returned error: %v", err)
	}
	_ = stream.Close()

	if authorizer.request.AgentSessionToken != "agent-token" || authorizer.request.ResourceID != "res-web" || authorizer.request.Protocol != "tcp" || authorizer.request.Port != 443 {
		t.Fatalf("authorization request = %+v", authorizer.request)
	}
	if tunnel.request.SessionID != "sess-1" || tunnel.request.SessionToken != "session-token" || tunnel.request.GatewayEndpoint != "gateway.example.test:9443" || tunnel.request.TargetHost != "100.64.0.3" {
		t.Fatalf("gateway request = %+v", tunnel.request)
	}
}

func TestResourceStreamConnectorRejectsNonAllowDecision(t *testing.T) {
	connector := &resourceStreamConnector{
		enrollment: &fakeEnrollmentRecordProvider{record: enrollment.EnrollmentRecord{DeviceID: "device-1"}},
		userSessions: &fakeAuthenticatedSessionProvider{
			session: usersession.AuthenticatedSession{AgentSessionToken: "agent-token"},
			found:   true,
		},
		authorizer: &fakeFlowAuthorizer{response: flowauthorization.AuthorizeResponse{
			Decision: flowauthorization.DecisionMFARequired,
			Reason:   "step-up required",
		}},
		tunnel: &fakeGatewayTunnel{},
	}

	_, err := connector.OpenResourceStream(context.Background(), trafficinterception.StreamRequest{ResourceID: "res-web", Protocol: "tcp", Port: 443, SyntheticIP: "100.64.0.3"})
	if err == nil {
		t.Fatalf("OpenResourceStream returned nil error")
	}
	if connector.tunnel.(*fakeGatewayTunnel).opened {
		t.Fatalf("gateway stream was opened for non-allow decision")
	}
}

func TestResourceStreamConnectorRequiresAuthenticatedSession(t *testing.T) {
	connector := &resourceStreamConnector{
		userSessions: &fakeAuthenticatedSessionProvider{},
	}
	_, err := connector.OpenResourceStream(context.Background(), trafficinterception.StreamRequest{ResourceID: "res-web"})
	if err == nil {
		t.Fatalf("OpenResourceStream returned nil error")
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
}

func (authorizer *fakeFlowAuthorizer) AuthorizeResource(_ context.Context, request flowauthorization.AuthorizeRequest) (flowauthorization.AuthorizeResponse, error) {
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
