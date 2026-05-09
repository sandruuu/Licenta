package tcpproxy

import (
	"bytes"
	"net"
	"testing"
)

func TestFlowHandshakeDataAndFIN(t *testing.T) {
	flow := NewFlow(net.ParseIP("10.0.0.25"), net.ParseIP("100.64.0.42"), 52000, 443)
	synAck := flow.HandleSYN(100)
	srcIP, dstIP, srcPort, dstPort, _, ack, flags, _, err := parseTestPacket(synAck)
	if err != nil {
		t.Fatalf("parse SYN-ACK: %v", err)
	}
	if !srcIP.Equal(net.ParseIP("100.64.0.42")) || !dstIP.Equal(net.ParseIP("10.0.0.25")) || srcPort != 443 || dstPort != 52000 || flags != FlagSYN|FlagACK || ack != 101 {
		t.Fatalf("unexpected SYN-ACK src=%s dst=%s ports=%d/%d flags=%x ack=%d", srcIP, dstIP, srcPort, dstPort, flags, ack)
	}

	flow.HandleACK()
	ackPacket, payload := flow.HandleData(101, []byte("hello"))
	if !bytes.Equal(payload, []byte("hello")) {
		t.Fatalf("payload = %q", payload)
	}
	_, _, _, _, _, ack, flags, _, err = parseTestPacket(ackPacket)
	if err != nil {
		t.Fatalf("parse ACK: %v", err)
	}
	if flags != FlagACK || ack != 106 {
		t.Fatalf("ACK flags=%x ack=%d", flags, ack)
	}

	fin := flow.HandleFIN(106)
	_, _, _, _, _, ack, flags, _, err = parseTestPacket(fin)
	if err != nil {
		t.Fatalf("parse FIN: %v", err)
	}
	if flags != FlagFIN|FlagACK || ack != 107 {
		t.Fatalf("FIN flags=%x ack=%d", flags, ack)
	}
}

func TestFlowBuildDataPacketsSegmentsPayload(t *testing.T) {
	flow := NewFlow(net.ParseIP("10.0.0.25"), net.ParseIP("100.64.0.42"), 52000, 443)
	flow.HandleSYN(100)
	flow.HandleACK()
	data := bytes.Repeat([]byte("a"), maxSegmentSize+3)
	packets := flow.BuildDataPackets(data)
	if len(packets) != 2 {
		t.Fatalf("packet count = %d", len(packets))
	}
	_, _, _, _, _, _, flags, payload, err := parseTestPacket(packets[0])
	if err != nil {
		t.Fatalf("parse first data packet: %v", err)
	}
	if flags != FlagPSH|FlagACK || len(payload) != maxSegmentSize {
		t.Fatalf("first packet flags=%x payload=%d", flags, len(payload))
	}
	_, _, _, _, _, _, flags, payload, err = parseTestPacket(packets[1])
	if err != nil {
		t.Fatalf("parse second data packet: %v", err)
	}
	if flags != FlagPSH|FlagACK || len(payload) != 3 {
		t.Fatalf("second packet flags=%x payload=%d", flags, len(payload))
	}
}

func parseTestPacket(packet []byte) (net.IP, net.IP, uint16, uint16, uint32, uint32, byte, []byte, error) {
	return ParsePacket(packet)
}
