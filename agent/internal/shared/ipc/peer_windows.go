//go:build windows

package ipc

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

type handleConn interface {
	Fd() uintptr
}

func peerIdentityForConnection(connection net.Conn) (PeerIdentity, bool) {
	if connection == nil {
		return PeerIdentity{}, false
	}
	handleProvider, ok := connection.(handleConn)
	if !ok {
		return PeerIdentity{}, false
	}
	identity, err := namedPipeClientIdentity(windows.Handle(handleProvider.Fd()))
	if err != nil {
		return PeerIdentity{VerificationError: err.Error()}, true
	}
	identity.Verified = true
	return identity, true
}

func namedPipeClientIdentity(pipe windows.Handle) (PeerIdentity, error) {
	if pipe == 0 || pipe == windows.InvalidHandle {
		return PeerIdentity{}, errors.New("ipc connection has no valid Windows handle")
	}
	var processID uint32
	if err := windows.GetNamedPipeClientProcessId(pipe, &processID); err != nil {
		return PeerIdentity{}, fmt.Errorf("get named pipe client process id: %w", err)
	}
	if processID == 0 {
		return PeerIdentity{}, errors.New("named pipe client process id is empty")
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, processID)
	if err != nil {
		return PeerIdentity{}, fmt.Errorf("open ipc client process %d: %w", processID, err)
	}
	defer windows.CloseHandle(process)

	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return PeerIdentity{}, fmt.Errorf("open ipc client process token: %w", err)
	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return PeerIdentity{}, fmt.Errorf("read ipc client token user: %w", err)
	}
	if tokenUser == nil || tokenUser.User.Sid == nil {
		return PeerIdentity{}, errors.New("ipc client token has no user SID")
	}
	userSID := strings.TrimSpace(tokenUser.User.Sid.String())
	if userSID == "" {
		return PeerIdentity{}, errors.New("ipc client user SID is empty")
	}
	logonSessionID, _ := tokenLogonSessionID(token)
	sessionID, _ := tokenSessionID(token)
	return PeerIdentity{
		ProcessID:             processID,
		UserSID:               userSID,
		WindowsLogonSessionID: logonSessionID,
		WindowsSessionID:      sessionID,
	}, nil
}

type tokenStatistics struct {
	TokenID            windows.LUID
	AuthenticationID   windows.LUID
	ExpirationTime     int64
	TokenType          uint32
	ImpersonationLevel uint32
	DynamicCharged     uint32
	DynamicAvailable   uint32
	GroupCount         uint32
	PrivilegeCount     uint32
	ModifiedID         windows.LUID
}

func tokenLogonSessionID(token windows.Token) (string, error) {
	var stats tokenStatistics
	var returned uint32
	err := windows.GetTokenInformation(token, windows.TokenStatistics, (*byte)(unsafe.Pointer(&stats)), uint32(unsafe.Sizeof(stats)), &returned)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%08x:%08x", uint32(stats.AuthenticationID.HighPart), stats.AuthenticationID.LowPart), nil
}

func tokenSessionID(token windows.Token) (string, error) {
	var sessionID uint32
	var returned uint32
	err := windows.GetTokenInformation(token, windows.TokenSessionId, (*byte)(unsafe.Pointer(&sessionID)), uint32(unsafe.Sizeof(sessionID)), &returned)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d", sessionID), nil
}
