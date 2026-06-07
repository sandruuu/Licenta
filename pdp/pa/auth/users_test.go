package auth

import (
	"testing"

	"pdp/models"
	"pdp/store"
)

func TestAuthenticateByEmail(t *testing.T) {
	dataStore := store.New(t.TempDir())
	if err := dataStore.InitDB(); err != nil {
		t.Fatalf("InitDB() error = %v", err)
	}
	defer dataStore.Close()

	users := NewUserManager(dataStore)
	created, err := users.Register(models.RegisterRequest{
		Username: "pdp_test_admin",
		Email:    "PDP-Admin@Demo.TrustCloud.Test",
		Password: "correct-password",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

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
