package auth

import (
	"fmt"
	"log"
	"strings"
	"time"

	"pdp/models"
	"pdp/store"
	"pdp/util"

	"golang.org/x/crypto/bcrypt"
)

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
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	user.LastLoginAt = time.Now()
	um.store.SaveUser(user)
	return user, nil
}

// EnrollMFA generates a TOTP secret for direct admin MFA enrollment. Browser
// step-up keeps pending enrollment secrets in the step-up challenge instead.
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

// ActivateTOTPSecret verifies and stores a freshly generated TOTP secret.
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
