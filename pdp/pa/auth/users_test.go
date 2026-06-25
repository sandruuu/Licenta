package auth

import (
	"strings"
	"testing"
	"time"

	"pdp/internal/testdb"
	"pdp/models"

	"golang.org/x/crypto/bcrypt"
)

func TestPasswordPolicyFollowsNISTLengthAndBlocklist(t *testing.T) {
	user := &models.User{
		ID:       "usr_policy",
		Username: "maria.sandru@mta.ro",
		Email:    "maria.sandru@mta.ro",
	}

	if _, err := validateNewPassword(user, "short password"); err == nil || !strings.Contains(err.Error(), "at least 15") {
		t.Fatalf("short password error = %v, want minimum length rejection", err)
	}
	if _, err := validateNewPassword(user, "passwordpassword"); err == nil || !strings.Contains(err.Error(), "commonly used") {
		t.Fatalf("common password error = %v, want blocklist rejection", err)
	} else if policyErr, ok := err.(*PasswordPolicyError); !ok || len(policyErr.Requirements) == 0 {
		t.Fatalf("common password error = %T %+v, want password policy details", err, err)
	}
	if _, err := validateNewPassword(user, "maria.sandru@mta.ro"); err == nil || !strings.Contains(err.Error(), "account information") {
		t.Fatalf("context password error = %v, want account information rejection", err)
	}
	if _, err := validateNewPassword(user, "correct horse battery"); err != nil {
		t.Fatalf("passphrase with spaces rejected: %v", err)
	}
}

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
