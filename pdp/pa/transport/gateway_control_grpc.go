package transport

import (
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"pdp/models"
	pagateway "pdp/pa/gateway"
	"pdp/runtime/redisstate"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	gatewayControlGRPCServiceName = "gateway.GatewayControlService"
	gatewayControlGRPCStreamPath  = "/gateway.GatewayControlService/ControlStream"

	gatewayControlCommandProvisionSession = pagateway.CommandProvisionSession
	gatewayControlCommandRevokeSession    = pagateway.CommandRevokeSession
	gatewayControlCommandHeartbeat        = pagateway.CommandHeartbeat

	gatewayControlMessageHello = "gateway_hello"
	gatewayControlMessageAck   = "ack"

	gatewayControlAckStatusOK = "ok"
)

var ErrGatewayControlNotConnected = pagateway.ErrControlNotConnected

type GatewayControlSession = pagateway.ProvisionedSession
type GatewayControlRegistry = pagateway.ControlRegistry

func NewGatewayControlRegistry(runtimeState *redisstate.Client) *GatewayControlRegistry {
	return pagateway.NewControlRegistry(runtimeState)
}

func sendGatewayControlCommand(stream grpc.ServerStream, command *structpb.Struct) error {
	if err := stream.SendMsg(command); err != nil {
		return fmt.Errorf("send gateway control command: %w", err)
	}
	ack := &structpb.Struct{}
	if err := stream.RecvMsg(ack); err != nil {
		return fmt.Errorf("receive gateway control ack: %w", err)
	}
	if strings.TrimSpace(structFieldString(ack, "type")) != gatewayControlMessageAck {
		return errors.New("gateway control response is not an acknowledgement")
	}
	commandID := strings.TrimSpace(structFieldString(command, "command_id"))
	ackCommandID := strings.TrimSpace(structFieldString(ack, "command_id"))
	if commandID == "" || ackCommandID != commandID {
		return fmt.Errorf("gateway control acknowledgement command_id mismatch: got %q want %q", ackCommandID, commandID)
	}
	if statusValue := strings.ToLower(strings.TrimSpace(structFieldString(ack, "status"))); statusValue != gatewayControlAckStatusOK {
		code := strings.TrimSpace(structFieldString(ack, "code"))
		message := strings.TrimSpace(structFieldString(ack, "message"))
		return fmt.Errorf("gateway rejected control command: status=%s code=%s message=%s", statusValue, code, message)
	}
	return nil
}

type gatewayControlGRPCServer interface {
	ControlStream(grpc.ServerStream) error
}

type gatewayControlGRPCService struct {
	server *Server
}

func (service *gatewayControlGRPCService) ControlStream(stream grpc.ServerStream) error {
	if service == nil || service.server == nil {
		return status.Error(codes.Internal, "gateway control service is not initialized")
	}
	peerCert, ok := clientCertificateFromGRPCContext(stream.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "client certificate required for gateway authentication")
	}
	gateway, statusCode, errorMessage := service.server.authenticateGatewayCertificate(peerCert)
	if statusCode != 0 {
		return status.Error(grpcCodeForHTTPStatus(statusCode), errorMessage)
	}
	hello := &structpb.Struct{}
	if err := stream.RecvMsg(hello); err != nil {
		return status.Errorf(codes.InvalidArgument, "receive gateway hello: %v", err)
	}
	if strings.TrimSpace(structFieldString(hello, "type")) != gatewayControlMessageHello {
		return status.Error(codes.InvalidArgument, "gateway_hello is required as the first control message")
	}
	helloGatewayID := strings.TrimSpace(structFieldString(hello, "gateway_id"))
	if helloGatewayID == "" || helloGatewayID != gateway.ID {
		return status.Error(codes.PermissionDenied, "gateway hello identity does not match mTLS enrollment")
	}
	endpoint := strings.TrimSpace(structFieldString(hello, "gateway_endpoint"))
	service.server.markGatewayControlConnected(gateway, endpoint)
	if service.server.gatewayControl == nil {
		service.server.gatewayControl = NewGatewayControlRegistry(service.server.pa.Runtime)
	}
	connection := service.server.gatewayControl.Register(gateway, endpoint)
	if connection == nil {
		return status.Error(codes.Internal, "register gateway control connection")
	}
	defer service.server.gatewayControl.Unregister(connection)
	log.Printf("[GATEWAY-CONTROL] Connected gateway control stream: id=%s fqdn=%s endpoint=%s", gateway.ID, gateway.FQDN, endpoint)
	err := connection.Serve(stream.Context(), func(command *structpb.Struct) error {
		return sendGatewayControlCommand(stream, command)
	})
	log.Printf("[GATEWAY-CONTROL] Gateway control stream ended: id=%s err=%v", gateway.ID, err)
	if errors.Is(err, pagateway.ErrControlStreamReplaced) {
		return status.Error(codes.Canceled, "gateway control stream was replaced")
	}
	return err
}

func (s *Server) markGatewayControlConnected(gateway *models.Gateway, endpoint string) {
	if s == nil || s.pa == nil || s.pa.Store == nil || gateway == nil {
		return
	}
	now := time.Now().UTC()
	gateway.LastSeenAt = now
	gateway.UpdatedAt = now
	if strings.TrimSpace(endpoint) != "" {
		gateway.ListenAddr = strings.TrimSpace(endpoint)
	}
	s.pa.Store.SaveGateway(gateway)
}

func (s *Server) authenticateGatewayCertificate(peerCert *x509.Certificate) (*models.Gateway, int, string) {
	if peerCert == nil {
		return nil, 401, "client certificate required for gateway authentication"
	}
	organizationID, gatewayID, ok := pagateway.GatewayCertificateIdentity(peerCert)
	if !ok {
		return nil, 401, "client certificate has no gateway URI SAN identity"
	}
	gateway, found := s.pa.Store.GetGateway(gatewayID)
	if !found || gateway.Status != "enrolled" {
		log.Printf("[AUTH] Rejected gateway request: gateway_id=%q not found or not enrolled", gatewayID)
		return nil, 403, "gateway not enrolled or certificate identity not recognized"
	}
	if strings.TrimSpace(gateway.OrganizationID) != organizationID {
		log.Printf("[AUTH] Rejected gateway request: gateway_id=%q organization mismatch cert=%q store=%q", gatewayID, organizationID, gateway.OrganizationID)
		return nil, 403, "gateway certificate organization does not match enrollment record"
	}
	if strings.TrimSpace(gateway.CertFingerprint) == "" {
		log.Printf("[AUTH] Rejected gateway request: gateway_id=%q enrolled but has no certificate fingerprint on record", gatewayID)
		return nil, 403, "gateway enrollment record is incomplete (missing certificate fingerprint)"
	}
	fingerprint := clientCertificateFingerprint(peerCert)
	if subtle.ConstantTimeCompare([]byte(fingerprint), []byte(gateway.CertFingerprint)) != 1 {
		log.Printf("[AUTH] Rejected gateway request: gateway_id=%q fingerprint mismatch", gatewayID)
		return nil, 403, "certificate fingerprint does not match enrollment record"
	}
	return gateway, 0, ""
}

func gatewayControlStreamHandler(server interface{}, stream grpc.ServerStream) error {
	return server.(gatewayControlGRPCServer).ControlStream(stream)
}

var gatewayControlGRPCServiceDesc = grpc.ServiceDesc{
	ServiceName: gatewayControlGRPCServiceName,
	HandlerType: (*gatewayControlGRPCServer)(nil),
	Streams: []grpc.StreamDesc{
		{StreamName: "ControlStream", Handler: gatewayControlStreamHandler, ServerStreams: true, ClientStreams: true},
	},
	Metadata: "gateway_control.proto",
}
