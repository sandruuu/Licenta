package controlplane

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/types/known/structpb"
)

const (
	gatewayTrustGRPCGetCACertificate  = "/gateway.GatewayTrustService/GetCACertificate"
	gatewayTrustGRPCGetRevokedSerials = "/gateway.GatewayTrustService/GetRevokedSerials"
	gatewayEnrollmentGRPCRenewCert    = "/gateway.GatewayEnrollmentService/RenewCertificate"
)

func (client *Client) GetCACert() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	response, err := client.invokeUnary(ctx, gatewayTrustGRPCGetCACertificate, &structpb.Struct{})
	if err != nil {
		return nil, fmt.Errorf("get PA CA cert over gRPC: %w", err)
	}
	caPEM := structFieldString(response, "ca_pem")
	if caPEM == "" {
		return nil, fmt.Errorf("PA gRPC response did not include ca_pem")
	}
	return []byte(caPEM), nil
}

func (client *Client) GetRevokedSerials() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	response, err := client.invokeUnary(ctx, gatewayTrustGRPCGetRevokedSerials, &structpb.Struct{})
	if err != nil {
		return nil, fmt.Errorf("get revoked serials over gRPC: %w", err)
	}
	serials, err := stringListField(response, "revoked_serials", true)
	if err != nil {
		return nil, fmt.Errorf("parse revoked serials: %w", err)
	}
	return serials, nil
}

type CertRenewalResponse struct {
	GatewayID string `json:"gateway_id,omitempty"`
	Status    string `json:"status"`
	CertPEM   string `json:"cert_pem"`
	CAPEM     string `json:"ca_pem"`
	Message   string `json:"message"`
}

func (client *Client) RenewCert(csrPEM string) (*CertRenewalResponse, error) {
	request, err := structpb.NewStruct(map[string]interface{}{"csr_pem": csrPEM})
	if err != nil {
		return nil, fmt.Errorf("build renewal request: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), client.renewalTimeout)
	defer cancel()

	response, err := client.invokeUnary(ctx, gatewayEnrollmentGRPCRenewCert, request)
	if err != nil {
		return nil, fmt.Errorf("renew cert: %w", err)
	}
	result := CertRenewalResponse{
		GatewayID: structFieldString(response, "gateway_id"),
		Status:    structFieldString(response, "status"),
		CertPEM:   structFieldString(response, "cert_pem"),
		CAPEM:     structFieldString(response, "ca_pem"),
		Message:   structFieldString(response, "message"),
	}
	if result.Status != "renewed" {
		return nil, fmt.Errorf("renewal failed: %s", result.Message)
	}
	return &result, nil
}
