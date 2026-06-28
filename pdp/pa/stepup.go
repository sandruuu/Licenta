package pa

import (
	"encoding/json"
	"fmt"
	"strings"
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
	stepUpExpiredStateGrace   = 2 * time.Minute
	maxStepUpFailedAttempts   = 5
	stepUpStateKind           = "step_up_challenge"
)

type StepUpManager struct {
	state RuntimeStateStore
}

type RuntimeStateStore interface {
	SaveEphemeralState(kind, key string, value []byte, expiresAt time.Time) error
	GetEphemeralState(kind, key string) ([]byte, bool)
	DeleteEphemeralState(kind, key string) error
	ListEphemeralState(kind string) (map[string][]byte, error)
}

type StepUpChallengeRequest struct {
	RequestID      string
	AgentSessionID string
	UserID         string
	Username       string
	OrganizationID string
	DeviceID       string
	ResourceID     string
	PolicyID       string
	PublicOrigin   string
	Requirement    *models.StepUpRequirement
}

type StepUpChallenge struct {
	ID                 string
	RequestID          string
	AgentSessionID     string
	UserID             string
	Username           string
	OrganizationID     string
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

func NewStepUpManager(state RuntimeStateStore) *StepUpManager {
	return &StepUpManager{state: state}
}

func (manager *StepUpManager) CreateChallenge(req StepUpChallengeRequest) (*StepUpChallenge, error) {
	if manager == nil || manager.state == nil {
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
	manager.expire(now)
	if existing := manager.findActive(req.AgentSessionID, req.UserID, req.DeviceID, req.ResourceID, req.PolicyID, now); existing != nil {
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
		RequestID:          strings.TrimSpace(req.RequestID),
		AgentSessionID:     strings.TrimSpace(req.AgentSessionID),
		UserID:             strings.TrimSpace(req.UserID),
		Username:           strings.TrimSpace(req.Username),
		OrganizationID:     strings.TrimSpace(req.OrganizationID),
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
		URL:                strings.TrimRight(strings.TrimSpace(req.PublicOrigin), "/") + "/verify/" + id,
		Reason:             strings.TrimSpace(requirement.Reason),
		CreatedAt:          now,
		ExpiresAt:          now.Add(defaultStepUpChallengeTTL),
	}
	if err := manager.save(challenge); err != nil {
		return nil, err
	}
	return cloneStepUpChallenge(challenge), nil
}

func (manager *StepUpManager) AuthContext(agentSessionID, userID, deviceID, resourceID string, now time.Time) models.AuthContext {
	if manager == nil || manager.state == nil {
		return models.AuthContext{}
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	manager.expire(now)
	var selected *StepUpChallenge
	for _, challenge := range manager.list() {
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

func (manager *StepUpManager) InvalidateCompletedAuthContext(userID, deviceID, resourceID, organizationID string) int {
	if manager == nil || manager.state == nil {
		return 0
	}
	userID = strings.TrimSpace(userID)
	deviceID = strings.TrimSpace(deviceID)
	resourceID = strings.TrimSpace(resourceID)
	organizationID = strings.TrimSpace(organizationID)
	if userID == "" || deviceID == "" || resourceID == "" {
		return 0
	}
	manager.expire(time.Now().UTC())
	invalidated := 0
	for _, challenge := range manager.list() {
		if challenge == nil || challenge.Status != StepUpStatusCompleted {
			continue
		}
		if !sameTrimmed(challenge.UserID, userID) ||
			!sameTrimmed(challenge.DeviceID, deviceID) ||
			!sameTrimmed(challenge.ResourceID, resourceID) {
			continue
		}
		if organizationID != "" && !sameTrimmed(challenge.OrganizationID, organizationID) {
			continue
		}
		if err := manager.state.DeleteEphemeralState(stepUpStateKind, challenge.ID); err == nil {
			invalidated++
		}
	}
	return invalidated
}

func (manager *StepUpManager) Get(id string) (*StepUpChallenge, bool) {
	if manager == nil || manager.state == nil {
		return nil, false
	}
	manager.expire(time.Now().UTC())
	challenge, ok := manager.load(strings.TrimSpace(id))
	if !ok || challenge == nil {
		return nil, false
	}
	return cloneStepUpChallenge(challenge), true
}

func (manager *StepUpManager) EnsurePendingTOTPSecret(challengeID string, generate func() (string, error)) (string, error) {
	if manager == nil || manager.state == nil {
		return "", fmt.Errorf("step-up manager is unavailable")
	}
	challenge, ok := manager.load(strings.TrimSpace(challengeID))
	if !ok || challenge == nil {
		return "", fmt.Errorf("step-up challenge not found")
	}
	now := time.Now().UTC()
	if manager.expirePendingChallenge(challenge, now) {
		_ = manager.save(challenge)
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
	if err := manager.save(challenge); err != nil {
		return "", err
	}
	return challenge.PendingTOTPSecret, nil
}

func (manager *StepUpManager) PendingTOTPSecret(challengeID string) (string, bool) {
	if manager == nil || manager.state == nil {
		return "", false
	}
	challenge, ok := manager.load(strings.TrimSpace(challengeID))
	if !ok || challenge == nil {
		return "", false
	}
	if manager.expirePendingChallenge(challenge, time.Now().UTC()) {
		_ = manager.save(challenge)
		return "", false
	}
	if !isPendingStepUpStatus(challenge.Status) || strings.TrimSpace(challenge.PendingTOTPSecret) == "" {
		return "", false
	}
	return challenge.PendingTOTPSecret, true
}

func (manager *StepUpManager) Complete(challengeID, method string, completedAt time.Time) (*StepUpChallenge, error) {
	return manager.CompleteWithAssurance(challengeID, StepUpCompletion{Method: method}, completedAt)
}

func (manager *StepUpManager) CompleteWithAssurance(challengeID string, completion StepUpCompletion, completedAt time.Time) (*StepUpChallenge, error) {
	if manager == nil || manager.state == nil {
		return nil, fmt.Errorf("step-up manager is unavailable")
	}
	challenge, ok := manager.load(strings.TrimSpace(challengeID))
	if !ok || challenge == nil {
		return nil, fmt.Errorf("step-up challenge not found")
	}
	if completedAt.IsZero() {
		completedAt = time.Now().UTC()
	}
	completedAt = completedAt.UTC()
	if manager.expirePendingChallenge(challenge, completedAt) {
		_ = manager.save(challenge)
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
	if err := manager.save(challenge); err != nil {
		return nil, err
	}
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
	if manager == nil || manager.state == nil {
		return nil, false
	}
	challenge, ok := manager.load(strings.TrimSpace(challengeID))
	if !ok || challenge == nil {
		return nil, false
	}
	now := time.Now().UTC()
	if manager.expirePendingChallenge(challenge, now) || !isPendingStepUpStatus(challenge.Status) {
		_ = manager.save(challenge)
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
		_ = manager.save(challenge)
		return cloneStepUpChallenge(challenge), false
	}
	_ = manager.save(challenge)
	return cloneStepUpChallenge(challenge), true
}

func (manager *StepUpManager) Deny(challengeID, reason string) {
	if manager == nil || manager.state == nil {
		return
	}
	challenge, ok := manager.load(strings.TrimSpace(challengeID))
	if !ok || challenge == nil {
		return
	}
	challenge.Status = StepUpStatusDenied
	challenge.Reason = strings.TrimSpace(reason)
	challenge.PendingTOTPSecret = ""
	_ = manager.save(challenge)
}

func (manager *StepUpManager) findActive(agentSessionID, userID, deviceID, resourceID, policyID string, now time.Time) *StepUpChallenge {
	for _, challenge := range manager.list() {
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

func (manager *StepUpManager) expire(now time.Time) {
	for _, challenge := range manager.list() {
		if challenge == nil || !stepUpExpiresAtOrBefore(challenge.ExpiresAt, now) {
			continue
		}
		switch challenge.Status {
		case StepUpStatusPending, StepUpStatusAwaiting:
			challenge.Status = StepUpStatusExpired
			challenge.PendingTOTPSecret = ""
			challenge.ExpiresAt = now.UTC().Add(time.Minute)
			_ = manager.save(challenge)
		case StepUpStatusCompleted, StepUpStatusDenied, StepUpStatusExpired:
			_ = manager.state.DeleteEphemeralState(stepUpStateKind, challenge.ID)
		}
	}
}

func (manager *StepUpManager) expirePendingChallenge(challenge *StepUpChallenge, now time.Time) bool {
	if challenge == nil || !isPendingStepUpStatus(challenge.Status) || !stepUpExpiresAtOrBefore(challenge.ExpiresAt, now) {
		return false
	}
	challenge.Status = StepUpStatusExpired
	challenge.PendingTOTPSecret = ""
	challenge.ExpiresAt = now.UTC().Add(time.Minute)
	return true
}

func (manager *StepUpManager) save(challenge *StepUpChallenge) error {
	if manager == nil || manager.state == nil || challenge == nil {
		return fmt.Errorf("step-up manager is unavailable")
	}
	raw, err := json.Marshal(challenge)
	if err != nil {
		return err
	}
	expiresAt := challenge.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = time.Now().UTC().Add(defaultStepUpChallengeTTL)
	}
	storageExpiresAt := expiresAt
	if isPendingStepUpStatus(challenge.Status) || challenge.Status == StepUpStatusExpired {
		storageExpiresAt = expiresAt.Add(stepUpExpiredStateGrace)
	}
	return manager.state.SaveEphemeralState(stepUpStateKind, challenge.ID, raw, storageExpiresAt)
}

func (manager *StepUpManager) load(id string) (*StepUpChallenge, bool) {
	if manager == nil || manager.state == nil {
		return nil, false
	}
	raw, ok := manager.state.GetEphemeralState(stepUpStateKind, strings.TrimSpace(id))
	if !ok {
		return nil, false
	}
	var challenge StepUpChallenge
	if err := json.Unmarshal(raw, &challenge); err != nil {
		_ = manager.state.DeleteEphemeralState(stepUpStateKind, id)
		return nil, false
	}
	return &challenge, true
}

func (manager *StepUpManager) list() []*StepUpChallenge {
	if manager == nil || manager.state == nil {
		return nil
	}
	values, err := manager.state.ListEphemeralState(stepUpStateKind)
	if err != nil {
		return nil
	}
	out := make([]*StepUpChallenge, 0, len(values))
	for key, raw := range values {
		var challenge StepUpChallenge
		if err := json.Unmarshal(raw, &challenge); err != nil {
			_ = manager.state.DeleteEphemeralState(stepUpStateKind, key)
			continue
		}
		out = append(out, &challenge)
	}
	return out
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
	copy.AllowedAAGUIDs = append([]string(nil), challenge.AllowedAAGUIDs...)
	return &copy
}

func sameTrimmed(left, right string) bool {
	return strings.EqualFold(strings.TrimSpace(left), strings.TrimSpace(right))
}
