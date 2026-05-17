package tcpproxy

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
)

const (
	FlagFIN byte = 0x01
	FlagSYN byte = 0x02
	FlagRST byte = 0x04
	FlagPSH byte = 0x08
	FlagACK byte = 0x10
)

const maxSegmentSize = 1400

type Flow struct {
	mu sync.Mutex

	srcIP   net.IP
	srcPort uint16
	dstIP   net.IP
	dstPort uint16

	ourSeq    uint32
	clientSeq uint32

	established bool
}

func NewFlow(srcIP, dstIP net.IP, srcPort, dstPort uint16) *Flow {
	return &Flow{
		srcIP:   append(net.IP{}, srcIP.To4()...),
		dstIP:   append(net.IP{}, dstIP.To4()...),
		srcPort: srcPort,
		dstPort: dstPort,
		ourSeq:  rand.Uint32(),
	}
}

func (flow *Flow) HandleSYN(clientISN uint32) []byte {
	flow.mu.Lock()
	defer flow.mu.Unlock()

	flow.clientSeq = clientISN + 1
	isn := flow.ourSeq
	flow.ourSeq = isn + 1
	return flow.reply(FlagSYN|FlagACK, isn, flow.clientSeq, nil, true)
}

func (flow *Flow) HandleACK() {
	flow.mu.Lock()
	defer flow.mu.Unlock()
	flow.established = true
}

func (flow *Flow) HandleData(seq uint32, payload []byte) ([]byte, []byte) {
	flow.mu.Lock()
	defer flow.mu.Unlock()

	if !flow.established || len(payload) == 0 {
		return nil, nil
	}
	if seq != flow.clientSeq {
		return flow.reply(FlagACK, flow.ourSeq, flow.clientSeq, nil, false), nil
	}
	flow.clientSeq += uint32(len(payload))
	return flow.reply(FlagACK, flow.ourSeq, flow.clientSeq, nil, false), append([]byte(nil), payload...)
}

func (flow *Flow) BuildDataPackets(data []byte) [][]byte {
	flow.mu.Lock()
	defer flow.mu.Unlock()

	packets := make([][]byte, 0, (len(data)+maxSegmentSize-1)/maxSegmentSize)
	for len(data) > 0 {
		size := len(data)
		if size > maxSegmentSize {
			size = maxSegmentSize
		}
		packet := flow.reply(FlagPSH|FlagACK, flow.ourSeq, flow.clientSeq, data[:size], false)
		flow.ourSeq += uint32(size)
		packets = append(packets, packet)
		data = data[size:]
	}
	return packets
}

func (flow *Flow) HandleFIN(seq uint32) []byte {
	flow.mu.Lock()
	defer flow.mu.Unlock()

	flow.clientSeq = seq + 1
	packet := flow.reply(FlagFIN|FlagACK, flow.ourSeq, flow.clientSeq, nil, false)
	flow.ourSeq++
	return packet
}

func (flow *Flow) BuildFIN() []byte {
	flow.mu.Lock()
	defer flow.mu.Unlock()

	packet := flow.reply(FlagFIN|FlagACK, flow.ourSeq, flow.clientSeq, nil, false)
	flow.ourSeq++
	return packet
}

func BuildRST(srcIP, dstIP net.IP, srcPort, dstPort uint16, ackSeq uint32) []byte {
	return buildPacket(dstIP.To4(), srcIP.To4(), dstPort, srcPort, 0, ackSeq, FlagRST|FlagACK, nil, false)
}

func (flow *Flow) reply(flags byte, seq, ack uint32, payload []byte, mss bool) []byte {
	return buildPacket(flow.dstIP, flow.srcIP, flow.dstPort, flow.srcPort, seq, ack, flags, payload, mss)
}

func buildPacket(fromIP, toIP net.IP, fromPort, toPort uint16, seq, ack uint32, flags byte, payload []byte, mss bool) []byte {
	ipHeaderLength := 20
	tcpHeaderLength := 20
	if mss {
		tcpHeaderLength = 24
	}
	totalLength := ipHeaderLength + tcpHeaderLength + len(payload)
	packet := make([]byte, totalLength)

	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLength))
	binary.BigEndian.PutUint16(packet[4:6], uint16(rand.Intn(0xffff)))
	packet[6] = 0x40
	packet[8] = 64
	packet[9] = 6
	copy(packet[12:16], fromIP)
	copy(packet[16:20], toIP)
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:ipHeaderLength]))

	tcp := packet[ipHeaderLength:]
	binary.BigEndian.PutUint16(tcp[0:2], fromPort)
	binary.BigEndian.PutUint16(tcp[2:4], toPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = byte(tcpHeaderLength/4) << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	if mss {
		tcp[20] = 2
		tcp[21] = 4
		binary.BigEndian.PutUint16(tcp[22:24], maxSegmentSize)
	}
	if len(payload) > 0 {
		copy(tcp[tcpHeaderLength:], payload)
	}
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(fromIP, toIP, tcp[:tcpHeaderLength+len(payload)]))
	return packet
}

func ParsePacket(packet []byte) (srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags byte, payload []byte, err error) {
	if len(packet) < 20 {
		err = fmt.Errorf("too short")
		return
	}
	if packet[0]>>4 != 4 || packet[9] != 6 {
		err = fmt.Errorf("not IPv4 TCP")
		return
	}
	ihl := int(packet[0]&0x0f) * 4
	if len(packet) < ihl+20 {
		err = fmt.Errorf("truncated")
		return
	}
	srcIP = append(net.IP{}, packet[12:16]...)
	dstIP = append(net.IP{}, packet[16:20]...)
	tcp := packet[ihl:]
	srcPort = binary.BigEndian.Uint16(tcp[0:2])
	dstPort = binary.BigEndian.Uint16(tcp[2:4])
	seq = binary.BigEndian.Uint32(tcp[4:8])
	ack = binary.BigEndian.Uint32(tcp[8:12])
	flags = tcp[13]
	tcpOffset := int(tcp[12]>>4) * 4
	if len(tcp) < tcpOffset {
		err = fmt.Errorf("truncated TCP header")
		return
	}
	if len(tcp) > tcpOffset {
		payload = append([]byte(nil), tcp[tcpOffset:]...)
	}
	return
}

func checksum(data []byte) uint16 {
	var sum uint32
	for index := 0; index < len(data)-1; index += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[index:]))
	}
	if len(data)&1 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func tcpChecksum(src, dst net.IP, segment []byte) uint16 {
	var pseudo []byte
	pseudo = append(pseudo, src.To4()...)
	pseudo = append(pseudo, dst.To4()...)
	pseudo = append(pseudo, 0, 6)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(segment)))
	pseudo = append(pseudo, length...)
	pseudo = append(pseudo, segment...)
	return checksum(pseudo)
}
