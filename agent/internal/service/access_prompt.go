package service

import (
	"strings"
	"time"

	flowauthorization "agent/internal/service/flow-authorization"
	trafficinterception "agent/internal/service/traffic-interception"
)

const signedOutAccessMessage = "Sign in required to access protected resources."

func (service *Service) recordAuthenticationRequired(request trafficinterception.StreamRequest) {
	if service == nil {
		return
	}
	message := signedOutAccessMessage
	target := firstNonEmpty(request.FQDN, request.ResourceID)
	if target != "" {
		message = "Sign in required to access " + target + "."
	}
	service.mu.Lock()
	service.accessPrompt = accessPromptState{
		Message:    message,
		ResourceID: strings.TrimSpace(request.ResourceID),
		FQDN:       strings.TrimSpace(request.FQDN),
		ReportedAt: service.clock().UTC(),
	}
	service.mu.Unlock()
}

func (service *Service) signedOutAccessPrompt(now time.Time) string {
	if service == nil {
		return signedOutAccessMessage
	}
	service.mu.RLock()
	prompt := service.accessPrompt
	service.mu.RUnlock()
	if strings.TrimSpace(prompt.Message) == "" {
		return signedOutAccessMessage
	}
	if !prompt.ReportedAt.IsZero() && now.UTC().Sub(prompt.ReportedAt.UTC()) > 5*time.Minute {
		return signedOutAccessMessage
	}
	return prompt.Message
}

func (service *Service) recordStepUpRequired(request trafficinterception.StreamRequest, authorization flowauthorization.AuthorizeResponse) {
	if service == nil || service.userSessions == nil {
		return
	}
	target := firstNonEmpty(request.FQDN, request.ResourceID)
	message := "Additional verification is required to access protected resources."
	if target != "" {
		message = "Additional verification is required to access " + target + "."
	}
	if reason := strings.TrimSpace(authorization.Reason); reason != "" {
		message = message + " " + reason
	}
	service.userSessions.SetAuthenticatedStepUp(message, authorization.StepUpURL)
}

func (service *Service) recordResourceAllowed(_ trafficinterception.StreamRequest, _ flowauthorization.AuthorizeResponse) {
	if service == nil || service.userSessions == nil {
		return
	}
	service.userSessions.ClearAuthenticatedStepUp()
}
