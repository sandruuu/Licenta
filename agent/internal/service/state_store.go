package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"ztna.local/agent/internal/deviceidentity"
	"ztna.local/agent/internal/ipc"
)

const (
	enrollmentStateFileVersion = 1
	defaultWindowsBaseDir      = "ztna"
	defaultEndpointSubdir      = "endpoint"
	defaultStateFileName       = "agent-enrollment-state.json"
)

var ErrEnrollmentStateNotFound = errors.New("enrollment state not found")

type EnrollmentStateStore interface {
	Load(context.Context) (persistedEnrollmentState, error)
	Save(context.Context, persistedEnrollmentState) error
}

type persistedEnrollmentState struct {
	Version             int                 `json:"version"`
	EnrollmentState     ipc.EnrollmentState `json:"enrollment_state"`
	DeviceID            string              `json:"device_id"`
	DeviceIDSource      string              `json:"device_id_source,omitempty"`
	ActiveUserSID       string              `json:"active_user_sid"`
	KeyName             string              `json:"key_name"`
	KeyProvider         string              `json:"key_provider"`
	CertificateSHA256   string              `json:"certificate_sha256"`
	CertificateNotAfter time.Time           `json:"certificate_not_after,omitempty"`
	LastAcceptedAt      time.Time           `json:"last_accepted_at,omitempty"`
	UpdatedAt           time.Time           `json:"updated_at"`
}

type fileEnrollmentStateStore struct {
	path  string
	clock func() time.Time
}

func newDefaultEnrollmentStateStore(clock func() time.Time) EnrollmentStateStore {
	return newFileEnrollmentStateStore(defaultEnrollmentStatePath(), clock)
}

func newFileEnrollmentStateStore(path string, clock func() time.Time) *fileEnrollmentStateStore {
	if clock == nil {
		clock = time.Now
	}
	return &fileEnrollmentStateStore{path: filepath.Clean(strings.TrimSpace(path)), clock: clock}
}

func defaultEnrollmentStatePath() string {
	return filepath.Join(defaultEnrollmentStateDir(), defaultStateFileName)
}

func defaultEnrollmentStateDir() string {
	if override := strings.TrimSpace(os.Getenv("ZTNA_AGENT_STATE_DIR")); override != "" {
		return filepath.Clean(override)
	}
	if override := strings.TrimSpace(os.Getenv("ZTNA_ENDPOINT_DIR")); override != "" {
		return filepath.Clean(override)
	}
	if legacyOverride := strings.TrimSpace(os.Getenv("ZTNA_TPM_DIR")); legacyOverride != "" {
		return filepath.Clean(legacyOverride)
	}
	if programData := strings.TrimSpace(os.Getenv("PROGRAMDATA")); programData != "" {
		return filepath.Join(programData, defaultWindowsBaseDir, defaultEndpointSubdir)
	}
	if runtime.GOOS == "windows" {
		return filepath.Join("C:\\ProgramData", defaultWindowsBaseDir, defaultEndpointSubdir)
	}
	return filepath.Join(string(filepath.Separator), "var", "lib", defaultWindowsBaseDir, defaultEndpointSubdir)
}

func (store *fileEnrollmentStateStore) Load(ctx context.Context) (persistedEnrollmentState, error) {
	if store == nil || strings.TrimSpace(store.path) == "" {
		return persistedEnrollmentState{}, ErrEnrollmentStateNotFound
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return persistedEnrollmentState{}, ctx.Err()
	default:
	}
	data, err := os.ReadFile(store.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return persistedEnrollmentState{}, ErrEnrollmentStateNotFound
		}
		return persistedEnrollmentState{}, fmt.Errorf("read enrollment state: %w", err)
	}
	var state persistedEnrollmentState
	if err := json.Unmarshal(data, &state); err != nil {
		return persistedEnrollmentState{}, fmt.Errorf("decode enrollment state: %w", err)
	}
	if err := state.validate(); err != nil {
		return persistedEnrollmentState{}, err
	}
	return state, nil
}

func (store *fileEnrollmentStateStore) Save(ctx context.Context, state persistedEnrollmentState) error {
	if store == nil || strings.TrimSpace(store.path) == "" {
		return errors.New("enrollment state path is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	state.Version = enrollmentStateFileVersion
	state.UpdatedAt = store.clock().UTC()
	if err := state.validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode enrollment state: %w", err)
	}
	data = append(data, '\n')
	dir := filepath.Dir(store.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create enrollment state directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".agent-enrollment-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create enrollment state temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("harden enrollment state temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write enrollment state temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync enrollment state temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close enrollment state temp file: %w", err)
	}
	if err := os.Rename(tmpName, store.path); err != nil {
		return fmt.Errorf("replace enrollment state file: %w", err)
	}
	return nil
}

func (state persistedEnrollmentState) validate() error {
	if state.Version != enrollmentStateFileVersion {
		return fmt.Errorf("unsupported enrollment state version %d", state.Version)
	}
	if state.EnrollmentState != ipc.EnrollmentStateEnrolled {
		return fmt.Errorf("unsupported persisted enrollment state %q", state.EnrollmentState)
	}
	if strings.TrimSpace(state.DeviceID) == "" {
		return errors.New("persisted device_id is required")
	}
	if strings.TrimSpace(state.ActiveUserSID) == "" {
		return errors.New("persisted active_user_sid is required")
	}
	if strings.TrimSpace(state.KeyName) == "" {
		return errors.New("persisted key_name is required")
	}
	keyProvider := strings.TrimSpace(state.KeyProvider)
	if keyProvider != "" && keyProvider != deviceidentity.MicrosoftPlatformCryptoProvider {
		return fmt.Errorf("unsupported persisted key provider %q", keyProvider)
	}
	return nil
}
