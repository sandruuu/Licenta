//go:build windows

package deviceidentity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	noActiveConsoleSession uint32  = 0xffffffff
	ncryptMachineKeyFlag           = 0x00000020
	ncryptSilentFlag               = 0x00000040
	nteBadKeyset           uintptr = 0x80090016
	nteNotFound            uintptr = 0x80090011
	pcpEKPublicProperty            = "PCP_EKPUB"
)

var (
	kernel32                         = windows.NewLazySystemDLL("kernel32.dll")
	wtsapi32                         = windows.NewLazySystemDLL("wtsapi32.dll")
	ncrypt                           = windows.NewLazySystemDLL("ncrypt.dll")
	procWTSGetActiveConsoleSessionID = kernel32.NewProc("WTSGetActiveConsoleSessionId")
	procWTSQueryUserToken            = wtsapi32.NewProc("WTSQueryUserToken")
	procNCryptOpenStorageProvider    = ncrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptOpenKey                = ncrypt.NewProc("NCryptOpenKey")
	procNCryptGetProperty            = ncrypt.NewProc("NCryptGetProperty")
	procNCryptFreeObject             = ncrypt.NewProc("NCryptFreeObject")
)

type platformProvider struct {
	fallbackUserSID string
	clock           func() time.Time
}

type ncryptHandle uintptr
type ncryptStatus uintptr

func newPlatformProvider(options Options) Provider {
	return &platformProvider{
		fallbackUserSID: strings.TrimSpace(options.AuthorizedUserSID),
		clock:           clockOrNow(options.Clock),
	}
}

func (provider *platformProvider) Snapshot(ctx context.Context) (Snapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return Snapshot{}, ctx.Err()
	default:
	}

	snapshot := Snapshot{
		KeyProvider: MicrosoftPlatformCryptoProvider,
		CollectedAt: provider.clock().UTC(),
	}
	var errs []error

	activeSID, err := activeConsoleUserSID()
	if err != nil {
		errs = append(errs, fmt.Errorf("active user SID: %w", err))
	}
	if activeSID == "" {
		activeSID = provider.fallbackUserSID
	}
	snapshot.ActiveUserSID = activeSID
	snapshot.KeyName = KeyNameForDevice()

	if snapshot.KeyName != "" {
		keyExists, err := machineKeyExists(snapshot.KeyName)
		if err != nil {
			errs = append(errs, fmt.Errorf("machine key lookup: %w", err))
		} else {
			snapshot.KeyExists = keyExists
		}
	}

	ekPublic, err := tpmEKPublic()
	if err != nil {
		errs = append(errs, fmt.Errorf("TPM EK public: %w", err))
	} else {
		deviceID, err := DeviceIDFromEKPublic(ekPublic)
		if err != nil {
			errs = append(errs, err)
		} else {
			snapshot.DeviceID = deviceID
			snapshot.DeviceIDSource = DeviceIDSourceTPMEKPublicSHA256
		}
	}

	if len(errs) > 0 {
		snapshot.LastError = joinErrorMessages(errs)
		return snapshot, errors.Join(errs...)
	}
	return snapshot, nil
}

func activeConsoleUserSID() (string, error) {
	sessionID, _, _ := procWTSGetActiveConsoleSessionID.Call()
	if uint32(sessionID) == noActiveConsoleSession {
		return "", errors.New("no active console session")
	}

	var tokenHandle windows.Handle
	ok, _, callErr := procWTSQueryUserToken.Call(sessionID, uintptr(unsafe.Pointer(&tokenHandle)))
	if ok == 0 {
		if callErr != windows.ERROR_SUCCESS {
			return "", callErr
		}
		return "", errors.New("WTSQueryUserToken failed")
	}
	defer windows.CloseHandle(tokenHandle)

	tokenUser, err := windows.Token(tokenHandle).GetTokenUser()
	if err != nil {
		return "", err
	}
	if tokenUser == nil || tokenUser.User.Sid == nil {
		return "", errors.New("active user token has no SID")
	}
	return tokenUser.User.Sid.String(), nil
}

func machineKeyExists(keyName string) (bool, error) {
	provider, err := openStorageProvider(MicrosoftPlatformCryptoProvider)
	if err != nil {
		return false, err
	}
	defer freeObject(provider)

	key, err := openMachineKey(provider, keyName)
	if err != nil {
		if isNCryptStatus(err, nteBadKeyset, nteNotFound) {
			return false, nil
		}
		return false, err
	}
	defer freeObject(key)
	return true, nil
}

func tpmEKPublic() ([]byte, error) {
	provider, err := openStorageProvider(MicrosoftPlatformCryptoProvider)
	if err != nil {
		return nil, err
	}
	defer freeObject(provider)
	return getPropertyBytes(provider, pcpEKPublicProperty)
}

func openStorageProvider(providerName string) (ncryptHandle, error) {
	name, err := windows.UTF16PtrFromString(providerName)
	if err != nil {
		return 0, err
	}
	var provider uintptr
	status, _, _ := procNCryptOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&provider)),
		uintptr(unsafe.Pointer(name)),
		0,
	)
	if status != 0 {
		return 0, ncryptStatus(status)
	}
	return ncryptHandle(provider), nil
}

func openMachineKey(provider ncryptHandle, keyName string) (ncryptHandle, error) {
	name, err := windows.UTF16PtrFromString(keyName)
	if err != nil {
		return 0, err
	}
	var key uintptr
	status, _, _ := procNCryptOpenKey.Call(
		uintptr(provider),
		uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(name)),
		0,
		ncryptMachineKeyFlag|ncryptSilentFlag,
	)
	if status != 0 {
		return 0, ncryptStatus(status)
	}
	return ncryptHandle(key), nil
}

func getPropertyBytes(handle ncryptHandle, property string) ([]byte, error) {
	name, err := windows.UTF16PtrFromString(property)
	if err != nil {
		return nil, err
	}
	var size uint32
	status, _, _ := procNCryptGetProperty.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(name)),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if status != 0 {
		return nil, ncryptStatus(status)
	}
	if size == 0 {
		return nil, errors.New("NCrypt property is empty")
	}
	buf := make([]byte, size)
	status, _, _ = procNCryptGetProperty.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if status != 0 {
		return nil, ncryptStatus(status)
	}
	return buf[:size], nil
}

func freeObject(handle ncryptHandle) {
	if handle != 0 {
		_, _, _ = procNCryptFreeObject.Call(uintptr(handle))
	}
}

func (status ncryptStatus) Error() string {
	return fmt.Sprintf("NCrypt status 0x%08x", uint32(status))
}

func isNCryptStatus(err error, statuses ...uintptr) bool {
	var status ncryptStatus
	if !errors.As(err, &status) {
		return false
	}
	for _, expected := range statuses {
		if uintptr(status) == expected {
			return true
		}
	}
	return false
}

func joinErrorMessages(errs []error) string {
	messages := make([]string, 0, len(errs))
	for _, err := range errs {
		if err != nil && strings.TrimSpace(err.Error()) != "" {
			messages = append(messages, err.Error())
		}
	}
	return strings.Join(messages, "; ")
}
