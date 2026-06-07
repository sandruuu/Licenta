package pa

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"pdp/models"
	"pdp/util"
)

const (
	StepUpStatusPending   = "pending"
	StepUpStatusAwaiting  = "awaiting_verification"
	StepUpStatusCompleted = "completed"
	StepUpStatusDenied    = "denied"
	StepUpStatusExpired   = "expired"

	defaultStepUpChallengeTTL = 5 * time.Minute
	maxStepUpFailedAttempts   = 5
)

type StepUpManager struct {
	mu         sync.RWMutex
	challenges map[string]*StepUpChallenge
}

type StepUpChallengeRequest struct {
	AgentSessionID string
	UserID         string
	Username       string
	TenantID       string
	DeviceID       string
	ResourceID     string
	PolicyID       string
	PublicOrigin   string
	Requirement    *models.StepUpRequirement
}

type StepUpChallenge struct {
	ID                 string
	AgentSessionID     string
	UserID             string
	Username           string
	TenantID           string
	DeviceID           string
	ResourceID         string
	PolicyID           string
	Status             string
	Methods            []string
	MinStrength        string
	WebAuthnAttachment string
	AllowedAAGUIDs     []string
	RequiredACR        string
	MaxAgeSeconds      int
	URL                string
	Reason             string

	CreatedAt           time.Time
	ExpiresAt           time.Time
	CompletedAt         time.Time
	CompletedMethod     string
	CompletedStrength   string
	CompletedAAGUID     string
	CompletedAttachment string
	FailedAttempts      int
	LastFailedAt        time.Time

	PendingTOTPSecret string
}

type StepUpCompletion struct {
	Method     string
	Strength   string
	AAGUID     string
	Attachment string
}

func NewStepUpManager() *StepUpManager {
	return &StepUpManager{challenges: make(map[string]*StepUpChallenge)}
}

func (manager *StepUpManager) CreateChallenge(req StepUpChallengeRequest) (*StepUpChallenge, error) {
	if manager == nil {
		return nil, fmt.Errorf("step-up manager is unavailable")
	}
	if strings.TrimSpace(req.AgentSessionID) == "" {
		return nil, fmt.Errorf("agent session id is required")
	}
	if strings.TrimSpace(req.UserID) == "" {
		return nil, fmt.Errorf("user id is required")
	}
	if strings.TrimSpace(req.DeviceID) == "" {
		return nil, fmt.Errorf("device id is required")
	}
	if strings.TrimSpace(req.ResourceID) == "" {
		return nil, fmt.Errorf("resource id is required")
	}
	requirement := req.Requirement
	if requirement == nil {
		requirement = &models.StepUpRequirement{}
	}

	now := time.Now().UTC()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.expireLocked(now)

	if existing := manager.findActiveLocked(req.AgentSessionID, req.UserID, req.DeviceID, req.ResourceID, req.PolicyID, now); existing != nil {
		return cloneStepUpChallenge(existing), nil
	}

	id, err := util.GenerateID("stepup")
	if err != nil {
		return nil, err
	}
	methods := models.StepUpMethods(requirement.Methods)
	maxAgeSeconds := models.StepUpMaxAgeSeconds(requirement.MaxAgeSeconds)
	challenge := &StepUpChallenge{
		ID:                 id,
		AgentSessionID:     strings.TrimSpace(req.AgentSessionID),
		UserID:             strings.TrimSpace(req.UserID),
		Username:           strings.TrimSpace(req.Username),
		TenantID:           strings.TrimSpace(req.TenantID),
		DeviceID:           strings.TrimSpace(req.DeviceID),
		ResourceID:         strings.TrimSpace(req.ResourceID),
		PolicyID:           firstNonEmptyString(req.PolicyID, requirement.PolicyID),
		Status:             StepUpStatusPending,
		Methods:            methods,
		MinStrength:        models.StepUpMinStrength(requirement.MinStrength),
		WebAuthnAttachment: strings.TrimSpace(requirement.WebAuthnAttachment),
		AllowedAAGUIDs:     append([]string(nil), requirement.AllowedAAGUIDs...),
		RequiredACR:        models.StepUpACR(requirement.RequiredACR),
		MaxAgeSeconds:      maxAgeSeconds,
		URL:                strings.TrimRight(strings.TrimSpace(req.PublicOrigin), "/") + "/browser/step-up/" + id,
		Reason:             strings.TrimSpace(requirement.Reason),
		CreatedAt:          now,
		ExpiresAt:          now.Add(defaultStepUpChallengeTTL),
	}
	manager.challenges[challenge.ID] = challenge
	return cloneStepUpChallenge(challenge), nil
}

func (manager *StepUpManager) AuthContext(agentSessionID, userID, deviceID, resourceID string, now time.Time) models.AuthContext {
	if manager == nil {
		return models.AuthContext{}
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.expireLocked(now)
	var selected *StepUpChallenge
	for _, challenge := range manager.challenges {
		if challenge == nil || challenge.Status != StepUpStatusCompleted {
			continue
		}
		if !sameTrimmed(challenge.AgentSessionID, agentSessionID) ||
			!sameTrimmed(challenge.UserID, userID) ||
			!sameTrimmed(challenge.DeviceID, deviceID) ||
			!sameTrimmed(challenge.ResourceID, resourceID) {
			continue
		}
		if !challenge.ExpiresAt.IsZero() && !now.Before(challenge.ExpiresAt) {
			continue
		}
		if selected == nil || challenge.CompletedAt.After(selected.CompletedAt) {
			selected = challenge
		}
	}
	if selected == nil {
		return models.AuthContext{}
	}
	return models.AuthContext{
		ACR:              selected.RequiredACR,
		AMR:              []string{selected.CompletedMethod},
		StepUpVerifiedAt: selected.CompletedAt,
		StepUpExpiresAt:  selected.ExpiresAt,
		StepUpMethod:     selected.CompletedMethod,
		StepUpStrength:   selected.CompletedStrength,
		StepUpAAGUID:     selected.CompletedAAGUID,
		StepUpAttachment: selected.CompletedAttachment,
	}
}

func (manager *StepUpManager) Get(id string) (*StepUpChallenge, bool) {
	if manager == nil {
		return nil, false
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.expireLocked(time.Now().UTC())
	challenge, ok := manager.challenges[strings.TrimSpace(id)]
	if !ok || challenge == nil {
		return nil, false
	}
	return cloneStepUpChallenge(challenge), true
}

func (manager *StepUpManager) EnsurePendingTOTPSecret(challengeID string, generate func() (string, error)) (string, error) {
	if manager == nil {
		return "", fmt.Errorf("step-up manager is unavailable")
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	challenge, ok := manager.challenges[strings.TrimSpace(challengeID)]
	if !ok || challenge == nil {
		return "", fmt.Errorf("step-up challenge not found")
	}
	now := time.Now().UTC()
	if manager.expirePendingChallengeLocked(challenge, now) {
		return "", fmt.Errorf("step-up challenge expired")
	}
	if !isPendingStepUpStatus(challenge.Status) {
		return "", fmt.Errorf("step-up challenge is not pending")
	}
	if strings.TrimSpace(challenge.PendingTOTPSecret) != "" {
		return challenge.PendingTOTPSecret, nil
	}
	if generate == nil {
		return "", fmt.Errorf("TOTP secret generator is unavailable")
	}
	secret, err := generate()
	if err != nil {
		return "", err
	}
	challenge.PendingTOTPSecret = strings.TrimSpace(secret)
	challenge.Status = StepUpStatusAwaiting
	return challenge.PendingTOTPSecret, nil
}

func (manager *StepUpManager) PendingTOTPSecret(challengeID string) (string, bool) {
	if manager == nil {
		return "", false
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	challenge := manager.challenges[strings.TrimSpace(challengeID)]
	if challenge == nil || manager.expirePendingChallengeLocked(challenge, time.Now().UTC()) || !isPendingStepUpStatus(challenge.Status) || strings.TrimSpace(challenge.PendingTOTPSecret) == "" {
		return "", false
	}
	return challenge.PendingTOTPSecret, true
}

func (manager *StepUpManager) Complete(challengeID, method string, completedAt time.Time) (*StepUpChallenge, error) {
	return manager.CompleteWithAssurance(challengeID, StepUpCompletion{Method: method}, completedAt)
}

func (manager *StepUpManager) CompleteWithAssurance(challengeID string, completion StepUpCompletion, completedAt time.Time) (*StepUpChallenge, error) {
	if manager == nil {
		return nil, fmt.Errorf("step-up manager is unavailable")
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	challenge, ok := manager.challenges[strings.TrimSpace(challengeID)]
	if !ok || challenge == nil {
		return nil, fmt.Errorf("step-up challenge not found")
	}
	if completedAt.IsZero() {
		completedAt = time.Now().UTC()
	}
	completedAt = completedAt.UTC()
	if manager.expirePendingChallengeLocked(challenge, completedAt) {
		return nil, fmt.Errorf("step-up challenge expired")
	}
	if !isPendingStepUpStatus(challenge.Status) {
		return nil, fmt.Errorf("step-up challenge is not pending")
	}
	challenge.Status = StepUpStatusCompleted
	challenge.CompletedAt = completedAt
	challenge.CompletedMethod = strings.ToLower(strings.TrimSpace(completion.Method))
	challenge.PendingTOTPSecret = ""
	if challenge.CompletedMethod == "" {
		challenge.CompletedMethod = "totp"
	}
	challenge.CompletedStrength = models.StepUpMinStrength(completion.Strength)
	if challenge.CompletedStrength == "" {
		challenge.CompletedStrength = stepUpStrengthForMethod(challenge.CompletedMethod)
	}
	challenge.CompletedAAGUID = strings.TrimSpace(completion.AAGUID)
	challenge.CompletedAttachment = strings.TrimSpace(completion.Attachment)
	challenge.ExpiresAt = challenge.CompletedAt.Add(time.Duration(models.StepUpMaxAgeSeconds(challenge.MaxAgeSeconds)) * time.Second)
	return cloneStepUpChallenge(challenge), nil
}

func stepUpStrengthForMethod(method string) string {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "webauthn":
		return models.StepUpStrengthPhishingResistant
	case "totp":
		return models.StepUpStrengthOTP
	default:
		return ""
	}
}

func (manager *StepUpManager) RecordFailedAttempt(challengeID, reason string) (*StepUpChallenge, bool) {
	if manager == nil {
		return nil, false
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	challenge, ok := manager.challenges[strings.TrimSpace(challengeID)]
	if !ok || challenge == nil {
		return nil, false
	}
	now := time.Now().UTC()
	if manager.expirePendingChallengeLocked(challenge, now) || !isPendingStepUpStatus(challenge.Status) {
		return cloneStepUpChallenge(challenge), false
	}
	challenge.FailedAttempts++
	challenge.LastFailedAt = now
	challenge.Reason = strings.TrimSpace(reason)
	if challenge.FailedAttempts >= maxStepUpFailedAttempts {
		challenge.Status = StepUpStatusDenied
		challenge.PendingTOTPSecret = ""
		if challenge.Reason == "" {
			challenge.Reason = "too many failed verification attempts"
		}
		return cloneStepUpChallenge(challenge), false
	}
	return cloneStepUpChallenge(challenge), true
}

func (manager *StepUpManager) Deny(challengeID, reason string) {
	if manager == nil {
		return
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if challenge := manager.challenges[strings.TrimSpace(challengeID)]; challenge != nil {
		challenge.Status = StepUpStatusDenied
		challenge.Reason = strings.TrimSpace(reason)
		challenge.PendingTOTPSecret = ""
	}
}

func (manager *StepUpManager) findActiveLocked(agentSessionID, userID, deviceID, resourceID, policyID string, now time.Time) *StepUpChallenge {
	for _, challenge := range manager.challenges {
		if challenge == nil {
			continue
		}
		if !sameTrimmed(challenge.AgentSessionID, agentSessionID) ||
			!sameTrimmed(challenge.UserID, userID) ||
			!sameTrimmed(challenge.DeviceID, deviceID) ||
			!sameTrimmed(challenge.ResourceID, resourceID) {
			continue
		}
		if strings.TrimSpace(policyID) != "" && !sameTrimmed(challenge.PolicyID, policyID) {
			continue
		}
		if !challenge.ExpiresAt.IsZero() && !now.Before(challenge.ExpiresAt) {
			continue
		}
		switch challenge.Status {
		case StepUpStatusPending, StepUpStatusAwaiting, StepUpStatusCompleted:
			return challenge
		}
	}
	return nil
}

func (manager *StepUpManager) expireLocked(now time.Time) {
	for id, challenge := range manager.challenges {
		if challenge == nil || !stepUpExpiresAtOrBefore(challenge.ExpiresAt, now) {
			continue
		}
		switch challenge.Status {
		case StepUpStatusPending, StepUpStatusAwaiting:
			challenge.Status = StepUpStatusExpired
			challenge.PendingTOTPSecret = ""
		case StepUpStatusCompleted, StepUpStatusDenied, StepUpStatusExpired:
			delete(manager.challenges, id)
		}
	}
}

func (manager *StepUpManager) expirePendingChallengeLocked(challenge *StepUpChallenge, now time.Time) bool {
	if challenge == nil || !isPendingStepUpStatus(challenge.Status) || !stepUpExpiresAtOrBefore(challenge.ExpiresAt, now) {
		return false
	}
	challenge.Status = StepUpStatusExpired
	challenge.PendingTOTPSecret = ""
	return true
}

func isPendingStepUpStatus(status string) bool {
	return status == StepUpStatusPending || status == StepUpStatusAwaiting
}

func stepUpExpiresAtOrBefore(expiresAt, now time.Time) bool {
	if expiresAt.IsZero() {
		return false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return !now.UTC().Before(expiresAt.UTC())
}

func cloneStepUpChallenge(challenge *StepUpChallenge) *StepUpChallenge {
	if challenge == nil {
		return nil
	}
	copy := *challenge
	copy.Methods = append([]string(nil), challenge.Methods...)
	return &copy
}

func sameTrimmed(left, right string) bool {
	return strings.EqualFold(strings.TrimSpace(left), strings.TrimSpace(right))
}
