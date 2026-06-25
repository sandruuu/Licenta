package transport

import (
	"context"
	"fmt"
	"strings"
	"time"

	"pdp/models"
	"pdp/pa/devices"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	deviceDataGRPCServiceName          = "trustagent.device.DeviceDataService"
	deviceDataGRPCReportDeviceDataPath = "/" + deviceDataGRPCServiceName + "/ReportDeviceData"
)

type deviceDataGRPCServer interface {
	ReportDeviceData(context.Context, *structpb.Struct) (*structpb.Struct, error)
}

type deviceDataGRPCService struct {
	server *Server
}

func (service *deviceDataGRPCService) ReportDeviceData(ctx context.Context, request *structpb.Struct) (*structpb.Struct, error) {
	if service == nil || service.server == nil {
		return nil, status.Error(codes.Internal, "device data service is not initialized")
	}
	enrollment, ok := deviceEnrollmentFromContextValue(ctx)
	if !ok || strings.TrimSpace(enrollment.DeviceID) == "" {
		return nil, status.Error(codes.PermissionDenied, "missing client certificate identity")
	}
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "device data report is required")
	}
	if service.server.pa == nil || service.server.pa.Devices == nil {
		return nil, status.Error(codes.Unavailable, devices.ErrServiceUnavailable.Error())
	}
	peerCert, ok := clientCertificateFromGRPCContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "client certificate required")
	}
	token := strings.TrimSpace(structFieldString(request, "agent_session_token"))
	if token == "" {
		return nil, status.Error(codes.Unauthenticated, "agent session token is required")
	}
	claims, err := service.server.pa.ValidateDeviceUserTokenBoundForScope(token, enrollment.DeviceID, clientCertificateFingerprint(peerCert), "device-data:write")
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	if sessionID := strings.TrimSpace(structFieldString(request, "agent_session_id")); sessionID != "" && sessionID != strings.TrimSpace(claims.SessionID) {
		return nil, status.Error(codes.PermissionDenied, "agent session id does not match token")
	}
	report, err := deviceDataReportFromStruct(request)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	report.OrganizationID = enrollment.OrganizationID
	report.UserID = strings.TrimSpace(claims.UserID)
	report.Username = strings.TrimSpace(claims.Username)
	report.AgentSessionID = strings.TrimSpace(claims.SessionID)
	report, err = service.server.pa.Devices.AcceptDeviceDataReportWithSourceIP(enrollment.DeviceID, report, grpcPeerIP(ctx))
	if err != nil {
		return nil, status.Error(grpcCodeForHTTPStatus(statusCodeForDeviceDataError(err)), err.Error())
	}
	return structpb.NewStruct(map[string]interface{}{
		"success":     true,
		"message":     "Device data report received",
		"reported_at": report.ReportedAt.UTC().Format(time.RFC3339Nano),
	})
}

func deviceDataReportFromStruct(value *structpb.Struct) (models.DeviceDataReport, error) {
	report := models.DeviceDataReport{
		DeviceID: strings.TrimSpace(structFieldString(value, "device_id")),
		Hostname: strings.TrimSpace(structFieldString(value, "hostname")),
		OS:       strings.TrimSpace(structFieldString(value, "os")),
	}
	if collectedAt := strings.TrimSpace(structFieldString(value, "collected_at")); collectedAt != "" {
		parsed, err := time.Parse(time.RFC3339Nano, collectedAt)
		if err != nil {
			return report, fmt.Errorf("collected_at must be RFC3339")
		}
		report.CollectedAt = parsed.UTC()
	}
	checksValue := value.GetFields()["checks"]
	if checksValue != nil && checksValue.GetListValue() != nil {
		for _, item := range checksValue.GetListValue().GetValues() {
			itemStruct := item.GetStructValue()
			if itemStruct == nil {
				continue
			}
			fields := itemStruct.GetFields()
			check := models.HealthCheck{
				Name:        strings.TrimSpace(valueString(fields["name"])),
				Status:      strings.TrimSpace(valueString(fields["status"])),
				Description: strings.TrimSpace(valueString(fields["description"])),
			}
			if details := fields["details"].GetStructValue(); details != nil {
				check.Details = make(map[string]string, len(details.GetFields()))
				for key, detailValue := range details.GetFields() {
					check.Details[key] = valueString(detailValue)
				}
			}
			report.Checks = append(report.Checks, check)
		}
	}
	return report, nil
}

func valueString(value *structpb.Value) string {
	if value == nil {
		return ""
	}
	return value.GetStringValue()
}

func deviceDataGRPCReportDeviceDataHandler(srv interface{}, ctx context.Context, decoder func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	request := &structpb.Struct{}
	if err := decoder(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(deviceDataGRPCServer).ReportDeviceData(ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: deviceDataGRPCReportDeviceDataPath}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(deviceDataGRPCServer).ReportDeviceData(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, request, info, handler)
}

var deviceDataGRPCServiceDesc = grpc.ServiceDesc{
	ServiceName: deviceDataGRPCServiceName,
	HandlerType: (*deviceDataGRPCServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "ReportDeviceData", Handler: deviceDataGRPCReportDeviceDataHandler},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "device_data.proto",
}
