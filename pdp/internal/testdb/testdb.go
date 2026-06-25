package testdb

import (
	"database/sql"
	"os"
	"strings"
	"testing"

	"pdp/store"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	testDatabaseURLEnv = "PDP_TEST_DATABASE_URL"
	databaseURLEnv     = "PDP_DATABASE_URL"
)

// NewStore opens an isolated PostgreSQL-backed store for integration-style tests.
func NewStore(t *testing.T) *store.Store {
	t.Helper()
	databaseURL := DatabaseURL(t)
	dataStore := store.NewWithDatabaseURL(t.TempDir(), databaseURL)
	if err := dataStore.InitDB(); err != nil {
		t.Fatalf("init PostgreSQL test store: %v", err)
	}
	Reset(t, databaseURL)
	t.Cleanup(func() { _ = dataStore.Close() })
	return dataStore
}

func DatabaseURL(t *testing.T) string {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv(testDatabaseURLEnv))
	if databaseURL == "" {
		databaseURL = strings.TrimSpace(os.Getenv(databaseURLEnv))
	}
	if databaseURL == "" {
		t.Skip("set PDP_TEST_DATABASE_URL or PDP_DATABASE_URL to run PostgreSQL-backed tests")
	}
	return databaseURL
}

func Reset(t *testing.T, databaseURL string) {
	t.Helper()
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("open PostgreSQL test database: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`TRUNCATE TABLE
		directory_group_members,
		directory_groups,
		directory_users,
		identity_provider_configs,
		mfa_recovery_codes,
		webauthn_credentials,
		login_locations,
		oidc_clients,
		gateways,
		device_users,
		revoked_certs,
		device_enrollments,
		revoked_tokens,
		device_data,
		audit_log,
		resources,
		sessions,
		policy_assignments,
		policy_rules,
		organization_memberships,
		organizations,
		users
		RESTART IDENTITY CASCADE`)
	if err != nil {
		t.Fatalf("reset PostgreSQL test database: %v", err)
	}
}
