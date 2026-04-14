package idp

import (
	"fmt"
	"log"
	"strings"
	"time"

	"cloud/models"
	"cloud/store"
	"cloud/util"

	"golang.org/x/crypto/bcrypt"
)

// UserManager handles user registration, authentication, and MFA enrollment
type UserManager struct {
	store *store.Store
}

// NewUserManager creates a new UserManager
func NewUserManager(s *store.Store) *UserManager {
	return &UserManager{store: s}
}

// Register creates a new user with a hashed password
func (um *UserManager) Register(req models.RegisterRequest) (*models.User, error) {
	// Validate input
	if strings.TrimSpace(req.Username) == "" {
		return nil, fmt.Errorf("username is required")
	}
	if len(req.Password) < 1 {
		return nil, fmt.Errorf("password is required")
	}
	if strings.TrimSpace(req.Email) == "" {
		return nil, fmt.Errorf("email is required")
	}

	// Check if username already exists
	if _, exists := um.store.GetUserByUsername(req.Username); exists {
		return nil, fmt.Errorf("username already exists")
	}

	// Hash the password with bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	// Generate unique user ID
	userID, err := util.GenerateID("usr")
	if err != nil {
		return nil, fmt.Errorf("generate user ID: %w", err)
	}

	user := &models.User{
		ID:           userID,
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		MFAMethods:   []string{},
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	um.store.SaveUser(user)
	log.Printf("[IDP] User registered: %s (%s)", user.Username, user.ID)
	return user, nil
}

// Authenticate validates the user's password (primary authentication factor)
func (um *UserManager) Authenticate(username, password string) (*models.User, error) {
	user, exists := um.store.GetUserByUsername(username)
	if !exists {
		return nil, fmt.Errorf("invalid credentials")
	}

	if user.Disabled {
		return nil, fmt.Errorf("account is disabled")
	}

	// Compare the provided password with the stored hash
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Update last login time
	user.LastLoginAt = time.Now()
	um.store.SaveUser(user)

	return user, nil
}

// EnrollMFA generates a new TOTP secret for the user and returns the enrollment data
func (um *UserManager) EnrollMFA(userID, issuer string) (*models.MFAEnrollResponse, error) {
	user, exists := um.store.GetUser(userID)
	if !exists {
		return nil, fmt.Errorf("user not found")
	}

	// Generate new TOTP secret
	secret, err := GenerateTOTPSecret()
	if err != nil {
		return nil, fmt.Errorf("generate TOTP secret: %w", err)
	}

	// Save the secret to the user (MFA is not yet enabled — needs verification)
	user.TOTPSecret = secret
	user.UpdatedAt = time.Now()
	um.store.SaveUser(user)

	// Build the otpauth URI for QR code scanning
	qrURI := BuildTOTPURI(secret, issuer, user.Username)

	log.Printf("[IDP] MFA enrollment initiated for user: %s", user.Username)

	return &models.MFAEnrollResponse{
		Secret:    secret,
		QRCodeURL: qrURI,
		Message:   "Scan the QR code with your authenticator app, then verify with a code to complete enrollment",
	}, nil
}

// ActivateMFA verifies a TOTP code and enables MFA for the user
func (um *UserManager) ActivateMFA(userID, code string) error {
	user, exists := um.store.GetUser(userID)
	if !exists {
		return fmt.Errorf("user not found")
	}

	if user.TOTPSecret == "" {
		return fmt.Errorf("MFA enrollment not initiated — call EnrollMFA first")
	}

	// Validate the TOTP code against the stored secret
	valid, err := ValidateTOTPCode(user.TOTPSecret, code)
	if err != nil {
		return fmt.Errorf("validate TOTP: %w", err)
	}
	if !valid {
		return fmt.Errorf("invalid TOTP code")
	}

	// Enable MFA — add "totp" to methods if not already present
	if !containsMethod(user.MFAMethods, "totp") {
		user.MFAMethods = append(user.MFAMethods, "totp")
	}
	user.UpdatedAt = time.Now()
	um.store.SaveUser(user)

	log.Printf("[IDP] MFA activated for user: %s", user.Username)
	return nil
}

// VerifyMFA validates a TOTP code for an MFA-enabled user
func (um *UserManager) VerifyMFA(userID, code string) error {
	user, exists := um.store.GetUser(userID)
	if !exists {
		return fmt.Errorf("user not found")
	}

	if !user.MFAEnabled() || user.TOTPSecret == "" {
		return fmt.Errorf("MFA is not enabled for this user")
	}

	valid, err := ValidateTOTPCode(user.TOTPSecret, code)
	if err != nil {
		return fmt.Errorf("validate TOTP: %w", err)
	}
	if !valid {
		return fmt.Errorf("invalid TOTP code")
	}

	log.Printf("[IDP] MFA verified for user: %s", user.Username)
	return nil
}

// GetUser returns a user by ID
func (um *UserManager) GetUser(id string) (*models.User, bool) {
	return um.store.GetUser(id)
}

// GetUserByUsername returns a user by username
func (um *UserManager) GetUserByUsername(username string) (*models.User, bool) {
	return um.store.GetUserByUsername(username)
}

// ListUsers returns all users
func (um *UserManager) ListUsers() []*models.User {
	return um.store.ListUsers()
}

// SetUserRole updates a user's role
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
		if v == m {
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
	log.Printf("[IDP] MFA method '%s' added for user %s", method, user.Username)
}

// FindOrCreateFederatedUser looks up a user by external subject + auth source.
// If found, it updates the last login time. If not found, it provisions a new
// user with no password (federated users authenticate via external IdP only).
func (um *UserManager) FindOrCreateFederatedUser(externalSubject, authSource, username, email string) (*models.User, error) {
	// Look up by externalSubject + authSource
	user, exists := um.store.GetUserByExternalSubject(externalSubject, authSource)
	if exists {
		user.LastLoginAt = time.Now()
		if username != "" && user.Username != username {
			user.Username = username
		}
		if email != "" && user.Email != email {
			user.Email = email
		}
		user.UpdatedAt = time.Now()
		um.store.SaveUser(user)
		log.Printf("[IDP] Federated user found: %s (source=%s, sub=%s)", user.Username, authSource, externalSubject)
		return user, nil
	}

	// Also check by username to avoid conflicts
	if existing, found := um.store.GetUserByUsername(username); found {
		// Username exists but with different auth source — conflict
		if existing.ExternalSubject != externalSubject || existing.AuthSource != authSource {
			return nil, fmt.Errorf("username '%s' already exists with different auth source", username)
		}
		// Same user, update
		existing.LastLoginAt = time.Now()
		existing.UpdatedAt = time.Now()
		um.store.SaveUser(existing)
		return existing, nil
	}

	// Auto-provision new federated user
	userID, err := util.GenerateID("usr")
	if err != nil {
		return nil, fmt.Errorf("generate user ID: %w", err)
	}

	now := time.Now()
	user = &models.User{
		ID:              userID,
		Username:        username,
		Email:           email,
		PasswordHash:    "", // no password for federated users
		MFAMethods:      []string{},
		Role:            "user",
		ExternalSubject: externalSubject,
		AuthSource:      authSource,
		CreatedAt:       now,
		UpdatedAt:       now,
		LastLoginAt:     now,
	}

	um.store.SaveUser(user)
	log.Printf("[IDP] Federated user provisioned: %s (source=%s, sub=%s, id=%s)", username, authSource, externalSubject, userID)
	return user, nil
}
