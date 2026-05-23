package wfpcontrol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

const (
	payloadMagic   uint32 = 0x46574154 // TAWF, little-endian on the wire.
	payloadVersion uint16 = 1

	protocolTCP uint8 = 6
	protocolUDP uint8 = 17
)

func encodeApplyRequest(request ApplyRequest) ([]byte, error) {
	proxyIP := net.ParseIP(strings.TrimSpace(request.ProxyAddress)).To4()
	if proxyIP == nil {
		return nil, fmt.Errorf("proxy address %q is not an IPv4 address", request.ProxyAddress)
	}
	if request.ProxyPort <= 0 || request.ProxyPort > 65535 {
		return nil, fmt.Errorf("proxy port %d is outside TCP/UDP range", request.ProxyPort)
	}
	if request.ProxyPID == 0 {
		return nil, errors.New("proxy PID is required")
	}
	buffer := new(bytes.Buffer)
	write := func(value any) error {
		return binary.Write(buffer, binary.LittleEndian, value)
	}
	if err := write(payloadMagic); err != nil {
		return nil, err
	}
	if err := write(payloadVersion); err != nil {
		return nil, err
	}
	flags := uint16(0)
	if request.FailClosed {
		flags |= 1
	}
	if err := write(flags); err != nil {
		return nil, err
	}
	if err := write(binary.BigEndian.Uint32(proxyIP)); err != nil {
		return nil, err
	}
	if err := write(uint16(request.ProxyPort)); err != nil {
		return nil, err
	}
	if err := write(uint16(0)); err != nil {
		return nil, err
	}
	if err := write(request.ProxyPID); err != nil {
		return nil, err
	}
	if err := write(uint32(len(request.Rules))); err != nil {
		return nil, err
	}
	for _, rule := range request.Rules {
		ip := net.ParseIP(strings.TrimSpace(rule.SyntheticIP)).To4()
		if ip == nil {
			return nil, fmt.Errorf("synthetic IP %q is not an IPv4 address", rule.SyntheticIP)
		}
		port := uint16(0)
		if rule.Port > 0 {
			if rule.Port > 65535 {
				return nil, fmt.Errorf("rule port %d is outside TCP/UDP range", rule.Port)
			}
			port = uint16(rule.Port)
		}
		protocol, err := protocolNumber(rule.Protocol)
		if err != nil {
			return nil, err
		}
		if err := write(binary.BigEndian.Uint32(ip)); err != nil {
			return nil, err
		}
		if err := write(port); err != nil {
			return nil, err
		}
		if err := write(protocol); err != nil {
			return nil, err
		}
		if err := write(uint8(0)); err != nil {
			return nil, err
		}
	}
	return buffer.Bytes(), nil
}

func decodeDestinationPayload(payload []byte) (Destination, error) {
	const destinationPayloadSize = 16
	if len(payload) < destinationPayloadSize {
		return Destination{}, errors.New("WFP destination response is truncated")
	}
	magic := binary.LittleEndian.Uint32(payload[0:4])
	if magic != payloadMagic {
		return Destination{}, errors.New("WFP destination response has invalid magic")
	}
	version := binary.LittleEndian.Uint16(payload[4:6])
	if version != payloadVersion {
		return Destination{}, fmt.Errorf("unsupported WFP destination response version %d", version)
	}
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, binary.LittleEndian.Uint32(payload[8:12]))
	port := int(binary.LittleEndian.Uint16(payload[12:14]))
	protocol := protocolName(payload[14])
	if protocol == "" {
		return Destination{}, fmt.Errorf("unsupported WFP destination protocol %d", payload[14])
	}
	return Destination{IP: ip.String(), Port: port, Protocol: protocol}, nil
}

func protocolNumber(value string) (uint8, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "tcp", "https", "http":
		return protocolTCP, nil
	case "udp":
		return protocolUDP, nil
	default:
		return 0, fmt.Errorf("unsupported interception protocol %q", value)
	}
}

func protocolName(value uint8) string {
	switch value {
	case protocolTCP:
		return "tcp"
	case protocolUDP:
		return "udp"
	default:
		return ""
	}
}
