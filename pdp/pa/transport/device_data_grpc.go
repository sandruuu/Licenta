package transport

import (
	"context"
	"errors"
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
	deviceDataGRPCHeartbeatPath        = "/" + deviceDataGRPCServiceName + "/Heartbeat"
)

type deviceDataGRPCServer interface {
	ReportDeviceData(context.Context, *structpb.Struct) (*structpb.Struct, error)
	Heartbeat(context.Context, *structpb.Struct) (*structpb.Struct, error)
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
	if _, hasScore := request.GetFields()["overall_score"]; hasScore {
		return nil, status.Error(codes.InvalidArgument, "overall_score is not accepted on raw device data reports")
	}
	report, err := deviceDataReportFromStruct(request)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	report.TenantID = enrollment.TenantID
	report, err = service.server.pa.Devices.AcceptDeviceDataReport(enrollment.DeviceID, report)
	if err != nil {
		return nil, status.Error(grpcCodeForHTTPStatus(statusCodeForDeviceDataError(err)), err.Error())
	}
	return structpb.NewStruct(map[string]interface{}{
		"success":     true,
		"message":     "Device data report received",
		"reported_at": report.ReportedAt.UTC().Format(time.RFC3339Nano),
	})
}

func (service *deviceDataGRPCService) Heartbeat(ctx context.Context, _ *structpb.Struct) (*structpb.Struct, error) {
	if service == nil || service.server == nil {
		return nil, status.Error(codes.Internal, "device data service is not initialized")
	}
	enrollment, ok := deviceEnrollmentFromContextValue(ctx)
	if !ok || strings.TrimSpace(enrollment.DeviceID) == "" {
		return nil, status.Error(codes.PermissionDenied, "missing client certificate identity")
	}
	if service.server.pa == nil || service.server.pa.Devices == nil {
		return nil, status.Error(codes.Unavailable, devices.ErrServiceUnavailable.Error())
	}
	reportedAt, err := service.server.pa.Devices.TouchDeviceDataHeartbeat(enrollment.DeviceID)
	if err != nil {
		if errors.Is(err, devices.ErrNoPriorDeviceData) {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		return nil, status.Error(grpcCodeForHTTPStatus(statusCodeForDeviceDataError(err)), err.Error())
	}
	return structpb.NewStruct(map[string]interface{}{
		"success":     true,
		"reported_at": reportedAt.Format(time.RFC3339Nano),
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

func deviceDataGRPCHeartbeatHandler(srv interface{}, ctx context.Context, decoder func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	request := &structpb.Struct{}
	if err := decoder(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(deviceDataGRPCServer).Heartbeat(ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: deviceDataGRPCHeartbeatPath}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(deviceDataGRPCServer).Heartbeat(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, request, info, handler)
}

var deviceDataGRPCServiceDesc = grpc.ServiceDesc{
	ServiceName: deviceDataGRPCServiceName,
	HandlerType: (*deviceDataGRPCServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "ReportDeviceData", Handler: deviceDataGRPCReportDeviceDataHandler},
		{MethodName: "Heartbeat", Handler: deviceDataGRPCHeartbeatHandler},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "device_data.proto",
}
