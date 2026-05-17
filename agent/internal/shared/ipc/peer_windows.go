//go:build windows

package ipc

import (
	"errors"
	"fmt"
	"net"
	"strings"

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
	userSID, err := namedPipeClientUserSID(windows.Handle(handleProvider.Fd()))
	if err != nil {
		return PeerIdentity{VerificationError: err.Error()}, true
	}
	return PeerIdentity{UserSID: userSID, Verified: true}, true
}

func namedPipeClientUserSID(pipe windows.Handle) (string, error) {
	if pipe == 0 || pipe == windows.InvalidHandle {
		return "", errors.New("ipc connection has no valid Windows handle")
	}
	var processID uint32
	if err := windows.GetNamedPipeClientProcessId(pipe, &processID); err != nil {
		return "", fmt.Errorf("get named pipe client process id: %w", err)
	}
	if processID == 0 {
		return "", errors.New("named pipe client process id is empty")
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, processID)
	if err != nil {
		return "", fmt.Errorf("open ipc client process %d: %w", processID, err)
	}
	defer windows.CloseHandle(process)

	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return "", fmt.Errorf("open ipc client process token: %w", err)
	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("read ipc client token user: %w", err)
	}
	if tokenUser == nil || tokenUser.User.Sid == nil {
		return "", errors.New("ipc client token has no user SID")
	}
	userSID := strings.TrimSpace(tokenUser.User.Sid.String())
	if userSID == "" {
		return "", errors.New("ipc client user SID is empty")
	}
	return userSID, nil
}
