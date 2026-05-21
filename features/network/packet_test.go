package network

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestParseIPv4TCPPacket(t *testing.T) {
	packet, err := ParseIPv4TCPPacket(testTCPPacket("10.0.0.25", "100.64.0.42", 52000, 443, TCPFlagSYN|TCPFlagACK, []byte("hello")))
	if err != nil {
		t.Fatalf("ParseIPv4TCPPacket returned error: %v", err)
	}
	if packet.SourceIP != "10.0.0.25" || packet.DestinationIP != "100.64.0.42" || packet.SourcePort != 52000 || packet.DestinationPort != 443 {
		t.Fatalf("packet = %+v", packet)
	}
	if packet.Flags != TCPFlagSYN|TCPFlagACK || !packet.IsSYN() || packet.PayloadLength() != 5 || string(packet.Payload) != "hello" {
		t.Fatalf("packet flags/payload = %+v", packet)
	}
}

func TestParseIPv4TCPPacketRejectsNonTCP(t *testing.T) {
	packet := testTCPPacket("10.0.0.25", "100.64.0.42", 52000, 443, TCPFlagSYN, nil)
	packet[9] = 17
	if _, err := ParseIPv4TCPPacket(packet); err == nil {
		t.Fatalf("ParseIPv4TCPPacket accepted non-TCP packet")
	}
}

func testTCPPacket(sourceIP, destinationIP string, sourcePort, destinationPort uint16, flags byte, payload []byte) []byte {
	const ipv4HeaderLength = 20
	const tcpHeaderLength = 20
	totalLength := ipv4HeaderLength + tcpHeaderLength + len(payload)
	packet := make([]byte, totalLength)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLength))
	packet[8] = 64
	packet[9] = 6
	copy(packet[12:16], net.ParseIP(sourceIP).To4())
	copy(packet[16:20], net.ParseIP(destinationIP).To4())
	tcp := packet[ipv4HeaderLength:]
	binary.BigEndian.PutUint16(tcp[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], destinationPort)
	binary.BigEndian.PutUint32(tcp[4:8], 100)
	binary.BigEndian.PutUint32(tcp[8:12], 200)
	tcp[12] = byte(tcpHeaderLength/4) << 4
	tcp[13] = flags
	copy(tcp[tcpHeaderLength:], payload)
	return packet
}
