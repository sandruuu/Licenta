package pa

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"agent/internal/service/enrollment"

	"google.golang.org/protobuf/types/known/structpb"
)

func (client *Client) ValidateEnrollmentAccessToken(ctx context.Context, input enrollment.ValidationInput) (*enrollment.ValidationResult, error) {
	if client == nil {
		return nil, errors.New("PA client is nil")
	}
	accessToken := strings.TrimSpace(input.AccessToken)
	if accessToken == "" {
		return nil, errors.New("access token is required")
	}
	request, err := structpb.NewStruct(map[string]interface{}{
		"device_id": strings.TrimSpace(input.DeviceID),
		"nonce":     strings.TrimSpace(input.Nonce),
	})
	if err != nil {
		return nil, fmt.Errorf("build enrollment validation request: %w", err)
	}
	var response structpb.Struct
	if err := client.invoke(ctx, agentEnrollmentValidateAccessTokenPath, request, &response, invokeOptions{AccessToken: accessToken}); err != nil {
		return nil, err
	}
	return enrollmentValidationFromStruct(&response, input)
}

func (client *Client) EnrollDevice(ctx context.Context, input enrollment.RemoteEnrollInput) (*enrollment.RemoteCertificateResult, error) {
	if client == nil {
		return nil, errors.New("PA client is nil")
	}
	accessToken := strings.TrimSpace(input.AccessToken)
	if accessToken == "" {
		return nil, errors.New("access token is required")
	}
	request, err := structpb.NewStruct(map[string]interface{}{
		"device_id":              strings.TrimSpace(input.DeviceID),
		"nonce":                  strings.TrimSpace(input.Nonce),
		"hostname":               strings.TrimSpace(input.Hostname),
		"user_email":             strings.TrimSpace(input.UserEmail),
		"csr_pem":                string(input.CSRPEM),
		"public_key_fingerprint": strings.TrimSpace(input.PublicKeyFingerprint),
		"key_proof":              strings.TrimSpace(input.KeyProof),
	})
	if err != nil {
		return nil, fmt.Errorf("build enrollment request: %w", err)
	}
	var response structpb.Struct
	if err := client.invoke(ctx, agentEnrollmentEnrollDevicePath, request, &response, invokeOptions{AccessToken: accessToken}); err != nil {
		return nil, err
	}
	return certificateResultFromStruct(&response)
}

func (client *Client) RenewDeviceCertificate(ctx context.Context, input enrollment.RemoteRenewalInput) (*enrollment.RemoteCertificateResult, error) {
	if client == nil {
		return nil, errors.New("PA client is nil")
	}
	request, err := structpb.NewStruct(map[string]interface{}{
		"device_id":              strings.TrimSpace(input.DeviceID),
		"hostname":               strings.TrimSpace(input.Hostname),
		"csr_pem":                string(input.CSRPEM),
		"public_key_fingerprint": strings.TrimSpace(input.PublicKeyFingerprint),
	})
	if err != nil {
		return nil, fmt.Errorf("build certificate renewal request: %w", err)
	}
	var response structpb.Struct
	if err := client.invoke(ctx, agentEnrollmentRenewCertificatePath, request, &response, invokeOptions{Certificate: &input.CurrentCertificate}); err != nil {
		return nil, err
	}
	return certificateResultFromStruct(&response)
}
func enrollmentValidationFromStruct(value *structpb.Struct, input enrollment.ValidationInput) (*enrollment.ValidationResult, error) {
	result := &enrollment.ValidationResult{
		DeviceID:  firstNonEmpty(structFieldString(value, "device_id"), input.DeviceID),
		Nonce:     firstNonEmpty(structFieldString(value, "nonce"), input.Nonce),
		UserEmail: strings.TrimSpace(structFieldString(value, "user_email")),
	}
	if expiresAt := strings.TrimSpace(structFieldString(value, "expires_at")); expiresAt != "" {
		parsed, err := time.Parse(time.RFC3339Nano, expiresAt)
		if err != nil {
			return nil, fmt.Errorf("parse enrollment validation expiry: %w", err)
		}
		result.ExpiresAt = parsed.UTC()
	}
	if result.DeviceID == "" {
		return nil, errors.New("enrollment validation response device_id is required")
	}
	if result.Nonce == "" {
		return nil, errors.New("enrollment validation response nonce is required")
	}
	return result, nil
}

func certificateResultFromStruct(value *structpb.Struct) (*enrollment.RemoteCertificateResult, error) {
	result := &enrollment.RemoteCertificateResult{
		ID:      strings.TrimSpace(structFieldString(value, "id")),
		CertPEM: []byte(strings.TrimSpace(structFieldString(value, "cert_pem"))),
		CAPEM:   []byte(strings.TrimSpace(structFieldString(value, "ca_pem"))),
	}
	if len(result.CertPEM) == 0 {
		return nil, errors.New("PA certificate response cert_pem is required")
	}
	return result, nil
}
