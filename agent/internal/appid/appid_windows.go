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
	for index := range rows {
		row := &rows[index]
		if tcpPort(row.LocalPort) != key.LocalPort || !ipv4Equal(tcpAddr(row.LocalAddr), localIP) {
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
	r1, _, callErr := procGetExtendedTCPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, afInet, tcpTableOwnerPIDAll, 0)
	if r1 != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) && size == 0 {
		if callErr != windows.ERROR_SUCCESS {
			return nil, fmt.Errorf("GetExtendedTcpTable size: %w", callErr)
		}
		return nil, errors.New("GetExtendedTcpTable returned empty size")
	}
	buffer := make([]byte, size)
	r1, _, callErr = procGetExtendedTCPTable.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0, afInet, tcpTableOwnerPIDAll, 0)
	if r1 != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable: %w", callErr)
	}
	count := *(*uint32)(unsafe.Pointer(&buffer[0]))
	rowSize := unsafe.Sizeof(mibTCPRowOwnerPID{})
	rows := make([]mibTCPRowOwnerPID, 0, count)
	base := unsafe.Add(unsafe.Pointer(&buffer[0]), unsafe.Sizeof(uint32(0)))
	for index := uint32(0); index < count; index++ {
		row := (*mibTCPRowOwnerPID)(unsafe.Add(base, uintptr(index)*rowSize))
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
	return identity, nil
}

func processImagePath(pid uint32) (string, error) {
	handle, err := windows.OpenProcess(processQueryLimited, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)
	buffer := make([]uint16, windows.MAX_PATH)
	for {
		size := uint32(len(buffer))
		err = windows.QueryFullProcessImageName(handle, 0, &buffer[0], &size)
		if err == nil {
			return windows.UTF16ToString(buffer[:size]), nil
		}
		if !strings.Contains(strings.ToLower(err.Error()), "more data") {
			return "", err
		}
		buffer = make([]uint16, len(buffer)*2)
	}
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func tcpAddr(addr uint32) net.IP {
	return net.IPv4(byte(addr), byte(addr>>8), byte(addr>>16), byte(addr>>24))
}

func tcpPort(port uint32) uint16 {
	return uint16((port&0xff)<<8 | (port>>8)&0xff)
}

func ipv4Equal(left, right net.IP) bool {
	left4 := left.To4()
	right4 := right.To4()
	if left4 == nil || right4 == nil {
		return false
	}
	return left4.Equal(right4)
}
