package routing

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"time"
)

type RouteManager struct {
	routes      []route
	interfaceIP string
}

type route struct {
	destination string
	mask        string
	gateway     string
}

func New(interfaceIP string) *RouteManager {
	return &RouteManager{
		interfaceIP: interfaceIP,
	}
}

func (r *RouteManager) AddCGNATRoute() error {
	return r.AddRoute("100.64.0.0", "255.192.0.0")
}

func (r *RouteManager) AddRoute(destination, mask string) error {
	nextHop := "0.0.0.0"
	rt := route{
		destination: destination,
		mask:        mask,
		gateway:     nextHop,
	}

	// First, delete any existing route to avoid conflicts with other interfaces
	del := exec.Command("route", "delete", destination)
	del.CombinedOutput() // ignore errors

	// Find the interface index for our TUN IP so the route binds to it explicitly.
	// We retry briefly because Windows may register the adapter IP asynchronously.
	ifIndex := waitForInterfaceIndex(r.interfaceIP, 20, 250*time.Millisecond)
	if ifIndex == "" {
		return fmt.Errorf("TUN interface index not found for %s", r.interfaceIP)
	}

	// Prefer an on-link route bound to the TUN interface index.
	// Using the adapter's own IP as a gateway can fail route/source selection
	// on some Windows setups, causing TCP connects to never reach the tunnel.
	args := []string{"add", destination, "mask", mask, nextHop, "metric", "5"}
	args = append(args, "IF", ifIndex)

	cmd := exec.Command("route", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Route add failed: %s — %w", strings.TrimSpace(string(output)), err)
	}

	r.routes = append(r.routes, rt)
	log.Printf("Added route: %s/%s via %s (IF %s, metric 5)", destination, mask, r.interfaceIP, ifIndex)
	return nil
}

func waitForInterfaceIndex(ip string, attempts int, pause time.Duration) string {
	for i := 0; i < attempts; i++ {
		ifIndex := findInterfaceIndex(ip)
		if ifIndex != "" {
			return ifIndex
		}
		time.Sleep(pause)
	}
	return ""
}

// findInterfaceIndex returns the Windows interface index for the given IP address.
func findInterfaceIndex(ip string) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.String() == ip {
					return fmt.Sprintf("%d", iface.Index)
				}
			}
		}
	}
	return ""
}

func (r *RouteManager) RemoveAllRoutes() {
	for _, rt := range r.routes {
		cmd := exec.Command("route", "delete", rt.destination)
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("Failed to remove route %s: %s — %v",
				rt.destination, strings.TrimSpace(string(output)), err)
		} else {
			log.Printf("Removed route: %s/%s", rt.destination, rt.mask)
		}
	}
	r.routes = nil
}
