// Package tcpproxy implements a minimal userspace TCP state machine for
// bridging raw TUN IP packets to TCP-level yamux streams.
//
// The gateway relay uses io.Copy (byte-stream level), so connect-app must
// strip IP/TCP headers before forwarding and reconstruct them on the return
// path. This package handles the TCP 3-way handshake, payload extraction,
// ACK generation, and packet construction with correct checksums.
package tcpproxy

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
)

// TCP flags
const (
	FlagFIN byte = 0x01
	FlagSYN byte = 0x02
	FlagRST byte = 0x04
	FlagPSH byte = 0x08
	FlagACK byte = 0x10
)

const maxSegmentSize = 1400

// Flow tracks the TCP state for a single connection between the local
// TUN client and a remote resource accessed via the yamux tunnel.
type Flow struct {
	mu sync.Mutex

	// Addressing — original direction: client → resource
	srcIP   net.IP // client TUN IP
	srcPort uint16
	dstIP   net.IP // CGNAT resource IP
	dstPort uint16

	// Sequence number tracking
	ourSeq    uint32 // next sequence number we will send
	clientSeq uint32 // next sequence number expected from client

	established bool
}

// NewFlow creates a new TCP flow state machine.
func NewFlow(srcIP, dstIP net.IP, srcPort, dstPort uint16) *Flow {
	return &Flow{
		srcIP:   append(net.IP{}, srcIP.To4()...),
		dstIP:   append(net.IP{}, dstIP.To4()...),
		srcPort: srcPort,
		dstPort: dstPort,
		ourSeq:  rand.Uint32(),
	}
}

// HandleSYN processes a client SYN and returns a SYN-ACK packet.
func (f *Flow) HandleSYN(clientISN uint32) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.clientSeq = clientISN + 1
	isn := f.ourSeq
	f.ourSeq = isn + 1 // SYN consumes one sequence number
	return f.reply(FlagSYN|FlagACK, isn, f.clientSeq, nil, true)
}

// HandleACK processes a pure ACK, completing the 3-way handshake.
func (f *Flow) HandleACK() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.established = true
}

// HandleData extracts payload from a data segment and returns an ACK packet.
// Returns (nil, nil) if the connection is not established or has no payload.
func (f *Flow) HandleData(seq uint32, payload []byte) (ackPkt []byte, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.established || len(payload) == 0 {
		return nil, nil
	}

	if seq != f.clientSeq {
		// Retransmission or out-of-order — send duplicate ACK
		return f.reply(FlagACK, f.ourSeq, f.clientSeq, nil, false), nil
	}

	f.clientSeq += uint32(len(payload))
	return f.reply(FlagACK, f.ourSeq, f.clientSeq, nil, false), payload
}

// BuildDataPackets wraps bytes received from the yamux stream into one or
// more TCP/IP packets suitable for injection into the TUN device.
func (f *Flow) BuildDataPackets(data []byte) [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()

	var pkts [][]byte
	for len(data) > 0 {
		n := len(data)
		if n > maxSegmentSize {
			n = maxSegmentSize
		}
		pkt := f.reply(FlagPSH|FlagACK, f.ourSeq, f.clientSeq, data[:n], false)
		f.ourSeq += uint32(n)
		pkts = append(pkts, pkt)
		data = data[n:]
	}
	return pkts
}

// HandleFIN processes a client FIN and returns a FIN-ACK packet.
func (f *Flow) HandleFIN(seq uint32) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.clientSeq = seq + 1
	pkt := f.reply(FlagFIN|FlagACK, f.ourSeq, f.clientSeq, nil, false)
	f.ourSeq++
	return pkt
}

// BuildFIN constructs a FIN packet to send to the client (when the yamux
// stream closes from the gateway side).
func (f *Flow) BuildFIN() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()

	pkt := f.reply(FlagFIN|FlagACK, f.ourSeq, f.clientSeq, nil, false)
	f.ourSeq++
	return pkt
}

// BuildRST creates a RST packet to reject a connection attempt.
// Used when the gateway returns auth_required.
func BuildRST(srcIP, dstIP net.IP, srcPort, dstPort uint16, ackSeq uint32) []byte {
	return buildPkt(dstIP.To4(), srcIP.To4(), dstPort, srcPort, 0, ackSeq, FlagRST|FlagACK, nil, false)
}

// reply constructs a TCP/IP reply packet from resource → client.
func (f *Flow) reply(flags byte, seq, ack uint32, payload []byte, mss bool) []byte {
	return buildPkt(f.dstIP, f.srcIP, f.dstPort, f.srcPort, seq, ack, flags, payload, mss)
}

// ---------- packet construction ----------

func buildPkt(fromIP, toIP net.IP, fromPort, toPort uint16, seq, ack uint32, flags byte, payload []byte, mss bool) []byte {
	ipHL := 20
	tcpHL := 20
	if mss {
		tcpHL = 24
	}
	total := ipHL + tcpHL + len(payload)
	p := make([]byte, total)

	// IPv4 header
	p[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(p[2:4], uint16(total))
	binary.BigEndian.PutUint16(p[4:6], uint16(rand.Intn(0xFFFF)))
	p[6] = 0x40 // Don't Fragment
	p[8] = 64   // TTL
	p[9] = 6    // TCP
	copy(p[12:16], fromIP)
	copy(p[16:20], toIP)
	// IP checksum (header only, checksum field is still 0)
	binary.BigEndian.PutUint16(p[10:12], ipCksum(p[:ipHL]))

	// TCP header
	t := p[ipHL:]
	binary.BigEndian.PutUint16(t[0:2], fromPort)
	binary.BigEndian.PutUint16(t[2:4], toPort)
	binary.BigEndian.PutUint32(t[4:8], seq)
	binary.BigEndian.PutUint32(t[8:12], ack)
	t[12] = byte(tcpHL/4) << 4
	t[13] = flags
	binary.BigEndian.PutUint16(t[14:16], 65535) // window
	if mss {
		t[20] = 2 // Kind: MSS
		t[21] = 4 // Length
		binary.BigEndian.PutUint16(t[22:24], maxSegmentSize)
	}
	if len(payload) > 0 {
		copy(t[tcpHL:], payload)
	}
	// TCP checksum (pseudo-header + segment, checksum field is still 0)
	binary.BigEndian.PutUint16(t[16:18], tcpCksum(fromIP, toIP, t[:tcpHL+len(payload)]))
	return p
}

func ipCksum(b []byte) uint16 {
	var s uint32
	for i := 0; i < len(b)-1; i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)&1 != 0 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s > 0xffff {
		s = (s >> 16) + (s & 0xffff)
	}
	return ^uint16(s)
}

func tcpCksum(src, dst net.IP, seg []byte) uint16 {
	var s uint32
	s += uint32(src[0])<<8 | uint32(src[1])
	s += uint32(src[2])<<8 | uint32(src[3])
	s += uint32(dst[0])<<8 | uint32(dst[1])
	s += uint32(dst[2])<<8 | uint32(dst[3])
	s += 6 // TCP protocol
	s += uint32(len(seg))
	for i := 0; i < len(seg)-1; i += 2 {
		s += uint32(binary.BigEndian.Uint16(seg[i:]))
	}
	if len(seg)&1 != 0 {
		s += uint32(seg[len(seg)-1]) << 8
	}
	for s > 0xffff {
		s = (s >> 16) + (s & 0xffff)
	}
	return ^uint16(s)
}

// ---------- packet parsing ----------

// ParsePacket extracts TCP fields from a raw IPv4 packet.
func ParsePacket(pkt []byte) (srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags byte, payload []byte, err error) {
	if len(pkt) < 20 {
		err = fmt.Errorf("too short")
		return
	}
	if pkt[9] != 6 {
		err = fmt.Errorf("not TCP")
		return
	}
	ihl := int(pkt[0]&0x0f) * 4
	if len(pkt) < ihl+20 {
		err = fmt.Errorf("truncated")
		return
	}
	srcIP = make(net.IP, 4)
	dstIP = make(net.IP, 4)
	copy(srcIP, pkt[12:16])
	copy(dstIP, pkt[16:20])

	tcp := pkt[ihl:]
	srcPort = binary.BigEndian.Uint16(tcp[0:2])
	dstPort = binary.BigEndian.Uint16(tcp[2:4])
	seq = binary.BigEndian.Uint32(tcp[4:8])
	ack = binary.BigEndian.Uint32(tcp[8:12])
	flags = tcp[13]
	off := int(tcp[12]>>4) * 4
	if len(tcp) > off {
		payload = tcp[off:]
	}
	return
}
