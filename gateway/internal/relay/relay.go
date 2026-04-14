package relay

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"gateway/store"
)

// Relay connects a client (via the tunnel) to an internal resource
// by establishing a TCP connection to the target and relaying data bidirectionally
type Relay struct {
	store *store.Store
}

// New creates a new Relay
func New(db *store.Store) *Relay {
	return &Relay{store: db}
}

// Connect establishes a TCP connection to a target internal resource
// and returns the connection for bidirectional data relay
func (r *Relay) Connect(targetIP string, targetPort int) (net.Conn, error) {
	addr := net.JoinHostPort(targetIP, fmt.Sprintf("%d", targetPort))

	log.Printf("[RELAY] Connecting to internal resource: %s", addr)

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", addr, err)
	}

	log.Printf("[RELAY] Connected to %s", addr)
	return conn, nil
}

// Bridge relays data bidirectionally between two connections
// Returns when either side closes or errors
func (r *Relay) Bridge(client net.Conn, target net.Conn) (clientToTarget int64, targetToClient int64) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Client → Target
	go func() {
		defer wg.Done()
		n, err := io.Copy(target, client)
		if err != nil {
			log.Printf("[RELAY] client→target error: %v", err)
		}
		clientToTarget = n
		// Signal target that client is done writing
		if tc, ok := target.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// Target → Client
	go func() {
		defer wg.Done()
		n, err := io.Copy(client, target)
		if err != nil {
			log.Printf("[RELAY] target→client error: %v", err)
		}
		targetToClient = n
		// Signal client that target is done writing
		if tc, ok := client.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
	return
}

// IsResourceAllowed checks if the target resource exists in the gateway config.
// It also resolves CGNAT tunnel IPs (100.64.x.x) to internal IPs.
func (r *Relay) IsResourceAllowed(targetIP string, targetPort int) bool {
	if res, _ := r.store.FindResourceByIP(targetIP, targetPort); res != nil {
		return true
	}
	// Try CGNAT tunnel IP resolution
	if res, _ := r.store.FindResourceByTunnelIP(targetIP, targetPort); res != nil {
		return true
	}
	return false
}

// ResolveTunnelIP translates a CGNAT tunnel IP to a real internal IP.
// If the IP is not a tunnel IP it is returned unchanged.
func (r *Relay) ResolveTunnelIP(tunnelIP string, port int) (internalIP string) {
	if res, _ := r.store.FindResourceByTunnelIP(tunnelIP, port); res != nil {
		log.Printf("[RELAY] CGNAT resolve: %s → %s", tunnelIP, res.InternalIP)
		return res.InternalIP
	}
	return tunnelIP // not a tunnel IP, passthrough
}

// GetResourceProtocol returns the protocol type for a resource
func (r *Relay) GetResourceProtocol(targetIP string, targetPort int) string {
	res, _ := r.store.FindResourceByIP(targetIP, targetPort)
	if res == nil {
		// Also try by tunnel IP
		res, _ = r.store.FindResourceByTunnelIP(targetIP, targetPort)
	}
	if res == nil {
		// Try to guess from port
		switch targetPort {
		case 3389:
			return "rdp"
		case 22:
			return "ssh"
		case 443:
			return "https"
		case 80:
			return "http"
		default:
			return "tcp"
		}
	}
	return res.Protocol
}
