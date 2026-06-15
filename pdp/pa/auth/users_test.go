package auth

import (
	"testing"
	"time"

	"pdp/internal/testdb"
	"pdp/models"

	"golang.org/x/crypto/bcrypt"
)

func TestAuthenticateByEmail(t *testing.T) {
	dataStore := testdb.NewStore(t)

	users := NewUserManager(dataStore)
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword() error = %v", err)
	}
	created := &models.User{
		ID:              "usr_test_admin",
		Username:        "pdp_test_admin",
		Email:           "PDP-Admin@Demo.TrustCloud.Test",
		PasswordHash:    string(passwordHash),
		MFAMethods:      []string{},
		Role:            "platform_admin",
		LastTOTPCounter: -1,
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}
	dataStore.SaveUser(created)

	authenticated, err := users.AuthenticateByEmail("pdp-admin@demo.trustcloud.test", "correct-password")
	if err != nil {
		t.Fatalf("AuthenticateByEmail() error = %v", err)
	}
	if authenticated.ID != created.ID {
		t.Fatalf("AuthenticateByEmail() user ID = %q, want %q", authenticated.ID, created.ID)
	}

	if _, err := users.AuthenticateByEmail("pdp_test_admin", "correct-password"); err == nil {
		t.Fatalf("AuthenticateByEmail() accepted username as email")
	}

	if _, err := users.Authenticate("pdp_test_admin", "correct-password"); err != nil {
		t.Fatalf("Authenticate() by username should still work for internal flows: %v", err)
	}
}
