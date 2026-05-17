package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"agent/internal/service/deviceidentity"
	"agent/internal/shared/ipc"
)

const (
	EnrollmentFileVersion = 1
	defaultWindowsBaseDir = "ztna"
	defaultEndpointSubdir = "endpoint"
	defaultStateFileName  = "agent-enrollment-state.json"
)

var ErrEnrollmentNotFound = errors.New("enrollment state not found")

type EnrollmentStore interface {
	Load(context.Context) (Enrollment, error)
	Save(context.Context, Enrollment) error
}

type Enrollment struct {
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

type EnrollmentFileStore struct {
	path  string
	clock func() time.Time
}

func NewDefaultEnrollmentStore(clock func() time.Time) EnrollmentStore {
	return NewEnrollmentFileStore(defaultEnrollmentStatePath(), clock)
}

func NewEnrollmentFileStore(path string, clock func() time.Time) *EnrollmentFileStore {
	if clock == nil {
		clock = time.Now
	}
	return &EnrollmentFileStore{path: filepath.Clean(strings.TrimSpace(path)), clock: clock}
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
	return filepath.Join("C:\\ProgramData", defaultWindowsBaseDir, defaultEndpointSubdir)
}

func (store *EnrollmentFileStore) Load(ctx context.Context) (Enrollment, error) {
	if store == nil || strings.TrimSpace(store.path) == "" {
		return Enrollment{}, ErrEnrollmentNotFound
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return Enrollment{}, ctx.Err()
	default:
	}
	data, err := os.ReadFile(store.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Enrollment{}, ErrEnrollmentNotFound
		}
		return Enrollment{}, fmt.Errorf("read enrollment state: %w", err)
	}
	var state Enrollment
	if err := json.Unmarshal(data, &state); err != nil {
		return Enrollment{}, fmt.Errorf("decode enrollment state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return Enrollment{}, err
	}
	return state, nil
}

func (store *EnrollmentFileStore) Save(ctx context.Context, state Enrollment) error {
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
	state.Version = EnrollmentFileVersion
	state.UpdatedAt = store.clock().UTC()
	if err := state.Validate(); err != nil {
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

func (state Enrollment) Validate() error {
	if state.Version != EnrollmentFileVersion {
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
