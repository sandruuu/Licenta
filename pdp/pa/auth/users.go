package auth

import (
	crand "crypto/rand"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"
	"unicode/utf8"

	"pdp/models"
	"pdp/store"
	"pdp/util"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/text/unicode/norm"
)

const (
	recoveryCodeCount    = 10
	recoveryCodeLength   = 12
	recoveryCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	passwordMinLength    = 15
	passwordMaxLength    = 256
)

// PasswordPolicyError describes a local password policy rejection.
type PasswordPolicyError struct {
	Message      string
	Requirements []string
}

func (e *PasswordPolicyError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

// PasswordPolicyRequirements returns the user-facing password rules enforced
// by the backend.
func PasswordPolicyRequirements() []string {
	return []string{
		"Use at least 15 characters.",
		"Use at most 256 characters.",
		"Do not use common, predictable, or repetitive passwords.",
		"Do not use account information such as the username or email address.",
	}
}

var commonPasswordBlocklist = map[string]string{
	"123456789":         "password is commonly used or predictable",
	"1234567890":        "password is commonly used or predictable",
	"123456789012345":   "password is commonly used or predictable",
	"111111111111111":   "password must not be a single repeated character",
	"aaaaaaaaaaaaaaa":   "password must not be a single repeated character",
	"administrator":     "password is commonly used or predictable",
	"adminadminadmin":   "password is commonly used or predictable",
	"letmeinletmein":    "password is commonly used or predictable",
	"passwordpassword":  "password is commonly used or predictable",
	"passwordpassword1": "password is commonly used or predictable",
	"qwertyqwerty":      "password is commonly used or predictable",
	"trustcloud":        "password is based on the service name",
	"trustcloudtrust":   "password is based on the service name",
	"trustcloud2026":    "password is based on the service name",
	"trust-cloud":       "password is based on the service name",
	"trust cloud":       "password is based on the service name",
}

// UserManager handles local user authentication and MFA enrollment.
type UserManager struct {
	store     *store.Store
	protector *SecretProtector
}

// NewUserManager creates a new UserManager.
func NewUserManager(s *store.Store, protectors ...*SecretProtector) *UserManager {
	var protector *SecretProtector
	if len(protectors) > 0 {
		protector = protectors[0]
	}
	return &UserManager{store: s, protector: protector}
}

// Authenticate validates the user's password.
func (um *UserManager) Authenticate(username, password string) (*models.User, error) {
	user, exists := um.store.GetUserByUsername(username)
	return um.authenticateUser(user, exists, password)
}

// AuthenticateByEmail validates the user's password using their email address.
func (um *UserManager) AuthenticateByEmail(email, password string) (*models.User, error) {
	user, exists := um.store.GetUserByEmail(email)
	return um.authenticateUser(user, exists, password)
}

// CompleteRequiredPasswordChange replaces an administrator password after first login.
func (um *UserManager) CompleteRequiredPasswordChange(userID, newPassword string) error {
	user, exists := um.store.GetUser(userID)
	if !exists {
		return fmt.Errorf("user not found")
	}
	if user.Disabled {
		return fmt.Errorf("account is disabled")
	}
	if !user.PasswordChangeRequired {
		return fmt.Errorf("password change is not required")
	}
	normalizedPassword, err := validateNewPassword(user, newPassword)
	if err != nil {
		return err
	}
	if strings.TrimSpace(user.PasswordHash) != "" {
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(normalizedPassword)); err == nil {
			return fmt.Errorf("new password must be different from the temporary password")
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(normalizedPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	now := time.Now()
	user.PasswordHash = string(hash)
	user.PasswordChangeRequired = false
	user.PasswordChangedAt = now
	user.UpdatedAt = now
	um.store.SaveUser(user)
	return nil
}

// VerifyPassword checks the current local password for a user.
func (um *UserManager) VerifyPassword(userID, password string) error {
	user, exists := um.store.GetUser(userID)
	if !exists {
		return fmt.Errorf("user not found")
	}
	if user.Disabled {
		return fmt.Errorf("account is disabled")
	}
	if strings.TrimSpace(user.PasswordHash) == "" {
		return fmt.Errorf("password is not configured for this account")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(normalizePassword(password))); err != nil {
		return fmt.Errorf("current password is invalid")
	}
	return nil
}

// ChangePassword replaces the password for an authenticated local user.
func (um *UserManager) ChangePassword(userID, currentPassword, newPassword string) error {
	user, exists := um.store.GetUser(userID)
	if !exists {
		return fmt.Errorf("user not found")
	}
	if user.Disabled {
		return fmt.Errorf("account is disabled")
	}
	if err := um.VerifyPassword(userID, currentPassword); err != nil {
		return err
	}
	normalizedPassword, err := validateNewPassword(user, newPassword)
	if err != nil {
		return err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(normalizedPassword)); err == nil {
		return fmt.Errorf("new password must be different from the current password")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(normalizedPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	now := time.Now()
	user.PasswordHash = string(hash)
	user.PasswordChangeRequired = false
	user.PasswordChangedAt = now
	user.UpdatedAt = now
	um.store.SaveUser(user)
	return nil
}

func (um *UserManager) authenticateUser(user *models.User, exists bool, password string) (*models.User, error) {
	if !exists {
		return nil, fmt.Errorf("invalid credentials")
	}
	if user.Disabled {
		return nil, fmt.Errorf("account is disabled")
	}
	if strings.TrimSpace(user.PasswordHash) == "" {
		return nil, fmt.Errorf("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(normalizePassword(password))); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	user.LastLoginAt = time.Now()
	um.store.SaveUser(user)
	return user, nil
}

func validateNewPassword(user *models.User, password string) (string, error) {
	normalized := normalizePassword(password)
	length := utf8.RuneCountInString(normalized)
	if length < passwordMinLength {
		return "", newPasswordPolicyError(fmt.Sprintf("password must contain at least %d characters", passwordMinLength))
	}
	if length > passwordMaxLength {
		return "", newPasswordPolicyError(fmt.Sprintf("password must contain at most %d characters", passwordMaxLength))
	}
	if reason := blockedPasswordReason(user, normalized); reason != "" {
		return "", newPasswordPolicyError(reason)
	}
	return normalized, nil
}

func newPasswordPolicyError(message string) *PasswordPolicyError {
	return &PasswordPolicyError{
		Message:      message,
		Requirements: PasswordPolicyRequirements(),
	}
}

func normalizePassword(password string) string {
	return norm.NFC.String(password)
}

func blockedPasswordReason(user *models.User, password string) string {
	key := passwordBlocklistKey(password)
	if key == "" {
		return "empty password"
	}
	if reason, blocked := commonPasswordBlocklist[key]; blocked {
		return reason
	}
	if isSingleRepeatedRune(key) {
		return "password must not be a single repeated character"
	}
	for _, value := range userPasswordBlocklistValues(user) {
		if key == passwordBlocklistKey(value) {
			return "password must not match account information"
		}
	}
	return ""
}

func passwordBlocklistKey(value string) string {
	return strings.ToLower(strings.TrimSpace(normalizePassword(value)))
}

func isSingleRepeatedRune(value string) bool {
	var first rune
	for index, r := range value {
		if index == 0 {
			first = r
			continue
		}
		if r != first {
			return false
		}
	}
	return first != 0
}

func userPasswordBlocklistValues(user *models.User) []string {
	if user == nil {
		return nil
	}
	values := []string{
		user.ID,
		user.Username,
		user.Email,
	}
	if localPart, _, ok := strings.Cut(user.Email, "@"); ok {
		values = append(values, localPart)
	}
	if localPart, _, ok := strings.Cut(user.Username, "@"); ok {
		values = append(values, localPart)
	}
	if user.OrganizationID != "" {
		values = append(values, user.OrganizationID)
	}
	return values
}

// EnrollMFA generates a TOTP secret for direct admin MFA enrollment.
func (um *UserManager) EnrollMFA(userID, issuer string) (*models.MFAEnrollResponse, error) {
	user, exists := um.store.GetUser(userID)
	if !exists {
		return nil, fmt.Errorf("user not found")
	}

	secret, err := um.unprotectMFAValue(user.TOTPSecret)
	if err != nil {
		return nil, fmt.Errorf("read TOTP secret: %w", err)
	}
	if secret == "" || containsMethod(user.MFAMethods, "totp") {
		secret, err = GenerateTOTPSecret()
		if err != nil {
			return nil, fmt.Errorf("generate TOTP secret: %w", err)
		}
	}

	existingSecret, _ := um.unprotectMFAValue(user.TOTPSecret)
	if existingSecret != secret {
		protectedSecret, err := um.protectMFAValue(secret)
		if err != nil {
			return nil, fmt.Errorf("protect TOTP secret: %w", err)
		}
		user.TOTPSecret = protectedSecret
		user.UpdatedAt = time.Now()
		um.store.SaveUser(user)
	}

	qrURI := BuildTOTPURI(secret, issuer, user.Username)
	qrImage, _ := BuildTOTPQRCodeImage(qrURI)
	log.Printf("[AUTH] MFA enrollment initiated for user: %s", user.Username)
	return &models.MFAEnrollResponse{
		Secret:      secret,
		QRCodeURL:   qrURI,
		QRCodeImage: qrImage,
		Message:     "Scan the QR code with your authenticator app, then verify with a code to complete enrollment",
	}, nil
}

// ActivateMFA verifies a pending TOTP code and enables TOTP for the user.
func (um *UserManager) ActivateMFA(userID, code string) error {
	user, exists := um.store.GetUser(userID)
	if !exists {
		return fmt.Errorf("user not found")
	}
	if strings.TrimSpace(user.TOTPSecret) == "" {
		return fmt.Errorf("MFA enrollment not initiated")
	}
	secret, err := um.unprotectMFAValue(user.TOTPSecret)
	if err != nil {
		return fmt.Errorf("read TOTP secret: %w", err)
	}
	return um.activateTOTPForUser(user, secret, code)
}

// ActivateTOTPSecret verifies and stores a new TOTP secret.
func (um *UserManager) ActivateTOTPSecret(userID, secret, code string) error {
	user, exists := um.store.GetUser(userID)
	if !exists {
		return fmt.Errorf("user not found")
	}
	return um.activateTOTPForUser(user, secret, code)
}

// VerifyMFA validates a TOTP code for a user with TOTP configured.
func (um *UserManager) VerifyMFA(userID, code string) error {
	user, exists := um.store.GetUser(userID)
	if !exists {
		return fmt.Errorf("user not found")
	}
	if !containsMethod(user.MFAMethods, "totp") || strings.TrimSpace(user.TOTPSecret) == "" {
		return fmt.Errorf("MFA is not enabled for this user")
	}

	secret, err := um.unprotectMFAValue(user.TOTPSecret)
	if err != nil {
		return fmt.Errorf("read TOTP secret: %w", err)
	}
	valid, counter, err := ValidateTOTPCodeWithCounter(secret, code, time.Now())
	if err != nil {
		return fmt.Errorf("validate TOTP: %w", err)
	}
	if !valid {
		return fmt.Errorf("invalid TOTP code")
	}
	if counter <= user.LastTOTPCounter {
		return fmt.Errorf("TOTP code has already been used")
	}
	user.LastTOTPCounter = counter
	user.UpdatedAt = time.Now()
	um.store.SaveUser(user)

	log.Printf("[AUTH] MFA verified for user: %s", user.Username)
	return nil
}

// GenerateRecoveryCodes replaces the user's existing MFA recovery codes.
func (um *UserManager) GenerateRecoveryCodes(userID string) ([]string, error) {
	user, exists := um.store.GetUser(userID)
	if !exists {
		return nil, fmt.Errorf("user not found")
	}
	if user.Disabled {
		return nil, fmt.Errorf("account is disabled")
	}
	if !user.MFAEnabled() {
		return nil, fmt.Errorf("MFA is not enabled for this user")
	}

	now := time.Now().UTC()
	plainCodes := make([]string, 0, recoveryCodeCount)
	records := make([]*models.MFARecoveryCode, 0, recoveryCodeCount)
	for i := 0; i < recoveryCodeCount; i++ {
		displayCode, normalizedCode, err := generateRecoveryCode()
		if err != nil {
			return nil, err
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(normalizedCode), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("hash recovery code: %w", err)
		}
		id, err := util.GenerateID("mrc")
		if err != nil {
			return nil, err
		}
		plainCodes = append(plainCodes, displayCode)
		records = append(records, &models.MFARecoveryCode{
			ID:        id,
			UserID:    user.ID,
			CodeHash:  string(hash),
			CreatedAt: now,
		})
	}
	if err := um.store.ReplaceMFARecoveryCodes(user.ID, records); err != nil {
		return nil, fmt.Errorf("save recovery codes: %w", err)
	}
	return plainCodes, nil
}

// VerifyRecoveryCode consumes a valid one-time recovery code for an MFA account.
func (um *UserManager) VerifyRecoveryCode(userID, code string) error {
	user, exists := um.store.GetUser(userID)
	if !exists {
		return fmt.Errorf("user not found")
	}
	if user.Disabled {
		return fmt.Errorf("account is disabled")
	}
	normalizedCode := normalizeRecoveryCode(code)
	if normalizedCode == "" {
		return fmt.Errorf("recovery code is required")
	}
	codes, err := um.store.ListActiveMFARecoveryCodes(user.ID)
	if err != nil {
		return fmt.Errorf("read recovery codes: %w", err)
	}
	for _, candidate := range codes {
		if candidate == nil || strings.TrimSpace(candidate.CodeHash) == "" {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(candidate.CodeHash), []byte(normalizedCode)) != nil {
			continue
		}
		if !um.store.MarkMFARecoveryCodeUsed(candidate.ID, time.Now().UTC()) {
			return fmt.Errorf("recovery code has already been used")
		}
		return nil
	}
	return fmt.Errorf("invalid recovery code")
}

// ResetMFAMethodForRecovery clears one MFA method after a recovery code is accepted.
func (um *UserManager) ResetMFAMethodForRecovery(userID, method string) error {
	user, exists := um.store.GetUser(userID)
	if !exists {
		return fmt.Errorf("user not found")
	}
	if user.Disabled {
		return fmt.Errorf("account is disabled")
	}
	method = strings.ToLower(strings.TrimSpace(method))
	switch method {
	case "totp":
		user.TOTPSecret = ""
		user.LastTOTPCounter = -1
		user.MFAMethods = removeMethod(user.MFAMethods, "totp")
	case "webauthn":
		user.MFAMethods = removeMethod(user.MFAMethods, "webauthn")
		if err := um.store.DeleteWebAuthnCredentialsForUser(user.ID); err != nil {
			return fmt.Errorf("delete WebAuthn credentials: %w", err)
		}
	default:
		return fmt.Errorf("unsupported MFA method")
	}
	user.UpdatedAt = time.Now()
	um.store.SaveUser(user)
	return nil
}

// GetUser returns a user by ID.
func (um *UserManager) GetUser(id string) (*models.User, bool) {
	return um.store.GetUser(id)
}

// GetUserByUsername returns a user by username.
func (um *UserManager) GetUserByUsername(username string) (*models.User, bool) {
	return um.store.GetUserByUsername(username)
}

// GetUserByEmail returns a user by email.
func (um *UserManager) GetUserByEmail(email string) (*models.User, bool) {
	return um.store.GetUserByEmail(email)
}

// ListUsers returns all users.
func (um *UserManager) ListUsers() []*models.User {
	return um.store.ListUsers()
}

// SetUserRole updates a user's role.
func (um *UserManager) SetUserRole(userID, role string) error {
	user, exists := um.store.GetUser(userID)
	if !exists {
		return fmt.Errorf("user not found")
	}
	user.Role = role
	user.UpdatedAt = time.Now()
	um.store.SaveUser(user)
	return nil
}

func containsMethod(methods []string, m string) bool {
	for _, v := range methods {
		if strings.EqualFold(strings.TrimSpace(v), strings.TrimSpace(m)) {
			return true
		}
	}
	return false
}

func removeMethod(methods []string, method string) []string {
	out := make([]string, 0, len(methods))
	for _, value := range methods {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(method)) {
			continue
		}
		out = append(out, value)
	}
	return out
}

func generateRecoveryCode() (string, string, error) {
	var builder strings.Builder
	builder.Grow(recoveryCodeLength)
	max := big.NewInt(int64(len(recoveryCodeAlphabet)))
	for i := 0; i < recoveryCodeLength; i++ {
		index, err := crand.Int(crand.Reader, max)
		if err != nil {
			return "", "", fmt.Errorf("generate recovery code: %w", err)
		}
		builder.WriteByte(recoveryCodeAlphabet[index.Int64()])
	}
	normalized := builder.String()
	return formatRecoveryCode(normalized), normalized, nil
}

func normalizeRecoveryCode(code string) string {
	var builder strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(code)) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func formatRecoveryCode(code string) string {
	code = normalizeRecoveryCode(code)
	if len(code) <= 4 {
		return code
	}
	parts := make([]string, 0, (len(code)+3)/4)
	for len(code) > 4 {
		parts = append(parts, code[:4])
		code = code[4:]
	}
	if code != "" {
		parts = append(parts, code)
	}
	return strings.Join(parts, "-")
}

// AddMFAMethod adds an MFA method to the user's list if not already present.
func (um *UserManager) AddMFAMethod(userID, method string) {
	user, exists := um.store.GetUser(userID)
	if !exists {
		return
	}
	if containsMethod(user.MFAMethods, method) {
		return
	}
	user.MFAMethods = append(user.MFAMethods, method)
	user.UpdatedAt = time.Now()
	um.store.SaveUser(user)
	log.Printf("[AUTH] MFA method '%s' added for user %s", method, user.Username)
}

// RemoveMFAMethod removes an MFA method from the user's method list.
func (um *UserManager) RemoveMFAMethod(userID, method string) {
	user, exists := um.store.GetUser(userID)
	if !exists {
		return
	}
	if !containsMethod(user.MFAMethods, method) {
		return
	}
	user.MFAMethods = removeMethod(user.MFAMethods, method)
	user.UpdatedAt = time.Now()
	um.store.SaveUser(user)
	log.Printf("[AUTH] MFA method '%s' removed for user %s", method, user.Username)
}

func (um *UserManager) ProtectMFAValue(value string) (string, error) {
	return um.protectMFAValue(value)
}

func (um *UserManager) UnprotectMFAValue(value string) (string, error) {
	return um.unprotectMFAValue(value)
}

func (um *UserManager) activateTOTPForUser(user *models.User, secret, code string) error {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return fmt.Errorf("MFA enrollment not initiated")
	}
	valid, counter, err := ValidateTOTPCodeWithCounter(secret, code, time.Now())
	if err != nil {
		return fmt.Errorf("validate TOTP: %w", err)
	}
	if !valid {
		return fmt.Errorf("invalid TOTP code")
	}
	protectedSecret, err := um.protectMFAValue(secret)
	if err != nil {
		return fmt.Errorf("protect TOTP secret: %w", err)
	}
	user.TOTPSecret = protectedSecret
	if !containsMethod(user.MFAMethods, "totp") {
		user.MFAMethods = append(user.MFAMethods, "totp")
	}
	user.LastTOTPCounter = counter
	user.UpdatedAt = time.Now()
	um.store.SaveUser(user)
	log.Printf("[AUTH] MFA activated for user: %s", user.Username)
	return nil
}

func (um *UserManager) protectMFAValue(value string) (string, error) {
	if um == nil || um.protector == nil {
		return strings.TrimSpace(value), nil
	}
	return um.protector.Protect(value)
}

func (um *UserManager) unprotectMFAValue(value string) (string, error) {
	if um == nil || um.protector == nil {
		return strings.TrimSpace(value), nil
	}
	return um.protector.Unprotect(value)
}

// FindOrCreateFederatedUser looks up a user by external subject and auth source.
func (um *UserManager) FindOrCreateFederatedUser(externalSubject, authSource, username, email, role, organizationID string) (*models.User, error) {
	if role == "" {
		role = "platform_admin"
	}

	user, exists := um.store.GetUserByExternalSubjectForOrganization(externalSubject, authSource, organizationID)
	if exists {
		if user.OrganizationID == "" {
			user.OrganizationID = organizationID
		}
		user.LastLoginAt = time.Now()
		if username != "" && user.Username != username {
			user.Username = username
		}
		if email != "" && user.Email != email {
			user.Email = email
		}
		if role != user.Role {
			log.Printf("[AUTH] Federated user role changed: %s %s -> %s (source=%s)", user.Username, user.Role, role, authSource)
			user.Role = role
		}
		user.UpdatedAt = time.Now()
		um.store.SaveUser(user)
		log.Printf("[AUTH] Federated user found: %s (source=%s, sub=%s, role=%s)", user.Username, authSource, externalSubject, user.Role)
		return user, nil
	}

	if existing, found := um.store.GetUserByUsername(username); found {
		sameOrganization := strings.TrimSpace(existing.OrganizationID) == strings.TrimSpace(organizationID)
		if sameOrganization {
			existing.ExternalSubject = externalSubject
			existing.AuthSource = authSource
			existing.LastLoginAt = time.Now()
			existing.UpdatedAt = existing.LastLoginAt
			if role != existing.Role {
				existing.Role = role
			}
			if email != "" && existing.Email != email {
				existing.Email = email
			}
			um.store.SaveUser(existing)
			log.Printf("[AUTH] Federated user linked: %s (source=%s, sub=%s, role=%s)", existing.Username, authSource, externalSubject, existing.Role)
			return existing, nil
		}
		if existing.ExternalSubject != externalSubject || existing.AuthSource != authSource {
			return nil, fmt.Errorf("username '%s' already exists with different auth source", username)
		}
		existing.LastLoginAt = time.Now()
		existing.UpdatedAt = time.Now()
		if role != existing.Role {
			existing.Role = role
		}
		um.store.SaveUser(existing)
		return existing, nil
	}

	userID, err := util.GenerateID("usr")
	if err != nil {
		return nil, fmt.Errorf("generate user ID: %w", err)
	}

	now := time.Now()
	user = &models.User{
		ID:              userID,
		Username:        username,
		Email:           email,
		PasswordHash:    "",
		MFAMethods:      []string{},
		Role:            role,
		OrganizationID:  organizationID,
		ExternalSubject: externalSubject,
		AuthSource:      authSource,
		LastTOTPCounter: -1,
		CreatedAt:       now,
		UpdatedAt:       now,
		LastLoginAt:     now,
	}

	um.store.SaveUser(user)
	log.Printf("[AUTH] Federated user provisioned: %s (source=%s, sub=%s, role=%s, id=%s)", username, authSource, externalSubject, role, userID)
	return user, nil
}
