package network

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	TCPFlagFIN byte = 0x01
	TCPFlagSYN byte = 0x02
	TCPFlagRST byte = 0x04
	TCPFlagPSH byte = 0x08
	TCPFlagACK byte = 0x10
)

var (
	ErrPacketTooShort  = errors.New("packet is too short")
	ErrPacketNotIPv4   = errors.New("packet is not IPv4")
	ErrPacketNotTCP    = errors.New("packet is not TCP")
	ErrPacketTruncated = errors.New("packet is truncated")
)

type Packet struct {
	SourceIP        string
	DestinationIP   string
	SourcePort      uint16
	DestinationPort uint16
	Sequence        uint32
	Acknowledgment  uint32
	Flags           byte
	Payload         []byte
}

func ParseIPv4TCPPacket(packet []byte) (Packet, error) {
	if len(packet) < 20 {
		return Packet{}, ErrPacketTooShort
	}
	if packet[0]>>4 != 4 {
		return Packet{}, ErrPacketNotIPv4
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength < 20 {
		return Packet{}, fmt.Errorf("%w: invalid IPv4 header length", ErrPacketTruncated)
	}
	totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLength == 0 {
		totalLength = len(packet)
	}
	if totalLength > len(packet) || totalLength < headerLength+20 {
		return Packet{}, ErrPacketTruncated
	}
	packet = packet[:totalLength]
	if packet[9] != 6 {
		return Packet{}, ErrPacketNotTCP
	}
	tcp := packet[headerLength:]
	tcpHeaderLength := int(tcp[12]>>4) * 4
	if tcpHeaderLength < 20 || len(tcp) < tcpHeaderLength {
		return Packet{}, ErrPacketTruncated
	}
	payload := append([]byte(nil), tcp[tcpHeaderLength:]...)
	return Packet{
		SourceIP:        net.IP(packet[12:16]).String(),
		DestinationIP:   net.IP(packet[16:20]).String(),
		SourcePort:      binary.BigEndian.Uint16(tcp[0:2]),
		DestinationPort: binary.BigEndian.Uint16(tcp[2:4]),
		Sequence:        binary.BigEndian.Uint32(tcp[4:8]),
		Acknowledgment:  binary.BigEndian.Uint32(tcp[8:12]),
		Flags:           tcp[13],
		Payload:         payload,
	}, nil
}

func (packet Packet) IsSYN() bool {
	return packet.Flags&TCPFlagSYN != 0
}

func (packet Packet) PayloadLength() int {
	return len(packet.Payload)
}
