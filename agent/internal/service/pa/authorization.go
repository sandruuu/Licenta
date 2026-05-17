package pa

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"agent/internal/service/relay"
	"agent/internal/service/tunnel"

	"google.golang.org/protobuf/types/known/structpb"
)

func (client *Client) AuthorizeResource(ctx context.Context, request relay.ResourceAuthorizationRequest) (relay.ResourceAuthorizationResult, error) {
	if client == nil {
		return relay.ResourceAuthorizationResult{}, errors.New("PA client is nil")
	}
	accessToken, deviceID := client.accessToken()
	if accessToken == "" {
		return relay.ResourceAuthorizationResult{}, errors.New("access token is required")
	}
	if deviceID == "" {
		return relay.ResourceAuthorizationResult{}, errors.New("device ID is required")
	}
	resourceID := strings.TrimSpace(request.ResourceID)
	if resourceID == "" {
		return relay.ResourceAuthorizationResult{}, errors.New("resource ID is required")
	}
	grpcRequest, err := authorizationRequestStruct(request)
	if err != nil {
		return relay.ResourceAuthorizationResult{}, fmt.Errorf("build authorization request: %w", err)
	}
	var response structpb.Struct
	if err := client.invoke(ctx, agentAuthorizationAuthorizeResourcePath, grpcRequest, &response, invokeOptions{AccessToken: accessToken, UseMachineCertificate: true}); err != nil {
		return relay.ResourceAuthorizationResult{}, err
	}
	return authorizationResultFromStruct(&response)
}
func authorizationRequestStruct(request relay.ResourceAuthorizationRequest) (*structpb.Struct, error) {
	payload := map[string]interface{}{
		"resource_id": strings.TrimSpace(request.ResourceID),
		"protocol":    strings.TrimSpace(request.Protocol),
	}
	if request.Port > 0 {
		payload["port"] = float64(request.Port)
	}
	if process := processIdentityMap(request.Process); process != nil {
		payload["process"] = process
	}
	return structpb.NewStruct(payload)
}

func processIdentityMap(process *tunnel.ProcessIdentity) map[string]interface{} {
	if process == nil {
		return nil
	}
	payload := make(map[string]interface{}, 5)
	if process.PID > 0 {
		payload["pid"] = float64(process.PID)
	}
	if strings.TrimSpace(process.Name) != "" {
		payload["name"] = strings.TrimSpace(process.Name)
	}
	if strings.TrimSpace(process.Path) != "" {
		payload["path"] = strings.TrimSpace(process.Path)
	}
	if strings.TrimSpace(process.SHA256) != "" {
		payload["sha256"] = strings.TrimSpace(process.SHA256)
	}
	if strings.TrimSpace(process.Signer) != "" {
		payload["signer"] = strings.TrimSpace(process.Signer)
	}
	if len(payload) == 0 {
		return nil
	}
	return payload
}

func authorizationResultFromStruct(response *structpb.Struct) (relay.ResourceAuthorizationResult, error) {
	decision := strings.TrimSpace(structFieldString(response, "decision"))
	if decision == "" {
		return relay.ResourceAuthorizationResult{}, errors.New("authorization response decision is required")
	}
	if decision != "allow" {
		return relay.ResourceAuthorizationResult{}, &DecisionError{Decision: decision, Reason: strings.TrimSpace(structFieldString(response, "reason")), RiskScore: int(structFieldNumberDefault(response, "risk_score")), MatchedRule: strings.TrimSpace(structFieldString(response, "matched_rule"))}
	}
	result := relay.ResourceAuthorizationResult{
		SessionID:       strings.TrimSpace(structFieldString(response, "session_id")),
		SessionToken:    strings.TrimSpace(structFieldString(response, "session_token")),
		ResourceID:      strings.TrimSpace(structFieldString(response, "resource_id")),
		Protocol:        strings.TrimSpace(structFieldString(response, "protocol")),
		Port:            int(structFieldNumberDefault(response, "port")),
		GatewayID:       strings.TrimSpace(structFieldString(response, "gateway_id")),
		GatewayEndpoint: strings.TrimSpace(structFieldString(response, "gateway_endpoint")),
	}
	if result.SessionID == "" || result.SessionToken == "" || result.ResourceID == "" {
		return relay.ResourceAuthorizationResult{}, errors.New("authorization response is missing strict session material")
	}
	if expiresAt := strings.TrimSpace(structFieldString(response, "expires_at")); expiresAt != "" {
		parsed, err := time.Parse(time.RFC3339Nano, expiresAt)
		if err != nil {
			return relay.ResourceAuthorizationResult{}, fmt.Errorf("parse authorization expiry: %w", err)
		}
		result.ExpiresAt = parsed.UTC()
	}
	return result, nil
}

type DecisionError struct {
	Decision    string
	Reason      string
	RiskScore   int
	MatchedRule string
}

func (err *DecisionError) Error() string {
	if err == nil {
		return "authorization failed"
	}
	decision := strings.TrimSpace(err.Decision)
	if decision == "" {
		decision = "deny"
	}
	reason := strings.TrimSpace(err.Reason)
	if reason == "" {
		reason = "policy administrator denied resource access"
	}
	return fmt.Sprintf("%s: %s", decision, reason)
}

func (err *DecisionError) ErrorCode() string {
	if err == nil || strings.TrimSpace(err.Decision) == "" {
		return "authorization_failed"
	}
	return strings.TrimSpace(err.Decision)
}
