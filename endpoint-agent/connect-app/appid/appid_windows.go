//go:build windows

package appid

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	afInet              = 2
	tcpTableOwnerPIDAll = 5
	tcpStateSynSent     = 3
	tcpStateEstablished = 5
	processQueryLimited = 0x1000
)

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

// LookupTCPProcess returns the Windows process that owns a TCP flow matching
// the supplied tuple. Exact tuple matching is attempted first; a local-port
// fallback is used for transient SYN races where Windows has not populated the
// remote tuple yet.
func LookupTCPProcess(key FlowKey) (*ProcessIdentity, error) {
	rows, err := tcpRows()
	if err != nil {
		return nil, err
	}

	localIP := key.LocalIP.To4()
	remoteIP := key.RemoteIP.To4()
	if localIP == nil || remoteIP == nil {
		return nil, fmt.Errorf("only IPv4 TCP flows are supported")
	}

	var fallback *mibTCPRowOwnerPID
	for i := range rows {
		row := &rows[i]
		if tcpPort(row.LocalPort) != key.LocalPort {
			continue
		}
		if !ipv4Equal(tcpAddr(row.LocalAddr), localIP) {
			continue
		}
		if ipv4Equal(tcpAddr(row.RemoteAddr), remoteIP) && tcpPort(row.RemotePort) == key.RemotePort {
			return processIdentity(row.OwningPID)
		}
		if fallback == nil && (row.State == tcpStateSynSent || row.State == tcpStateEstablished) {
			fallback = row
		}
	}
	if fallback != nil {
		return processIdentity(fallback.OwningPID)
	}
	return nil, fmt.Errorf("no owning process found for %s:%d -> %s:%d", localIP, key.LocalPort, remoteIP, key.RemotePort)
}

func tcpRows() ([]mibTCPRowOwnerPID, error) {
	var size uint32
	r1, _, callErr := procGetExtendedTCPTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		afInet,
		tcpTableOwnerPIDAll,
		0,
	)
	if r1 != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) && size == 0 {
		if callErr != windows.ERROR_SUCCESS {
			return nil, fmt.Errorf("GetExtendedTcpTable size: %w", callErr)
		}
		return nil, errors.New("GetExtendedTcpTable returned empty size")
	}

	buf := make([]byte, size)
	r1, _, callErr = procGetExtendedTCPTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		afInet,
		tcpTableOwnerPIDAll,
		0,
	)
	if r1 != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable: %w", callErr)
	}

	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibTCPRowOwnerPID{})
	rows := make([]mibTCPRowOwnerPID, 0, count)
	base := uintptr(unsafe.Pointer(&buf[0])) + unsafe.Sizeof(uint32(0))
	for i := uint32(0); i < count; i++ {
		row := (*mibTCPRowOwnerPID)(unsafe.Pointer(base + uintptr(i)*rowSize))
		rows = append(rows, *row)
	}
	return rows, nil
}

func processIdentity(pid uint32) (*ProcessIdentity, error) {
	identity := &ProcessIdentity{PID: pid}
	if pid == 0 {
		return identity, nil
	}

	path, err := processImagePath(pid)
	if err != nil {
		return identity, nil
	}
	identity.Path = path
	identity.Name = filepath.Base(path)
	if hash, err := fileSHA256(path); err == nil {
		identity.SHA256 = hash
	}
	// Signer extraction is intentionally left empty in this phase. The field is
	// part of the protocol so Authenticode metadata can be added later without a
	// wire-format change.
	return identity, nil
}

func processImagePath(pid uint32) (string, error) {
	handle, err := windows.OpenProcess(processQueryLimited, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)

	buf := make([]uint16, windows.MAX_PATH)
	for {
		size := uint32(len(buf))
		err = windows.QueryFullProcessImageName(handle, 0, &buf[0], &size)
		if err == nil {
			return windows.UTF16ToString(buf[:size]), nil
		}
		if !strings.Contains(strings.ToLower(err.Error()), "more data") {
			return "", err
		}
		buf = make([]uint16, len(buf)*2)
	}
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func tcpAddr(addr uint32) net.IP {
	return net.IPv4(byte(addr), byte(addr>>8), byte(addr>>16), byte(addr>>24))
}

func tcpPort(port uint32) uint16 {
	return uint16((port&0xff)<<8 | (port&0xff00)>>8)
}

func ipv4Equal(a, b net.IP) bool {
	aa := a.To4()
	bb := b.To4()
	return aa != nil && bb != nil && aa[0] == bb[0] && aa[1] == bb[1] && aa[2] == bb[2] && aa[3] == bb[3]
}
