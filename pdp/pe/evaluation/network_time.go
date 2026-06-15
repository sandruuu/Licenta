package evaluation

import (
	"bytes"
	"net"
	"strings"
	"time"
)

func matchesIPList(ipStr string, cidrs []string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, entry := range cidrs {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "-") && !strings.Contains(entry, "/") {
			if ipInRange(ip, entry) {
				return true
			}
			continue
		}
		if !strings.Contains(entry, "/") {
			if parsed := net.ParseIP(entry); parsed != nil && parsed.Equal(ip) {
				return true
			}
			continue
		}

		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func ipInRange(ip net.IP, entry string) bool {
	parts := strings.Split(entry, "-")
	if len(parts) != 2 {
		return false
	}
	start := net.ParseIP(strings.TrimSpace(parts[0]))
	end := net.ParseIP(strings.TrimSpace(parts[1]))
	if start == nil || end == nil {
		return false
	}
	family := ipFamily(start)
	if family == 0 || ipFamily(end) != family || ipFamily(ip) != family {
		return false
	}
	ipBytes := ip.To16()
	startBytes := start.To16()
	endBytes := end.To16()
	if family == 4 {
		ipBytes = ip.To4()
		startBytes = start.To4()
		endBytes = end.To4()
	}
	if bytes.Compare(startBytes, endBytes) > 0 {
		startBytes, endBytes = endBytes, startBytes
	}
	return bytes.Compare(ipBytes, startBytes) >= 0 && bytes.Compare(ipBytes, endBytes) <= 0
}

func ipFamily(ip net.IP) int {
	if ip == nil {
		return 0
	}
	if ip.To4() != nil {
		return 4
	}
	if ip.To16() != nil {
		return 6
	}
	return 0
}

func isWithinTimeWindowTZ(startStr, endStr string, now time.Time) bool {
	currentMinutes := now.Hour()*60 + now.Minute()
	start := parseTimeMinutes(startStr)
	end := parseTimeMinutes(endStr)

	if start == -1 || end == -1 {
		return true
	}
	if start <= end {
		return currentMinutes >= start && currentMinutes <= end
	}
	return currentMinutes >= start || currentMinutes <= end
}

func parseTimeMinutes(s string) int {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return -1
	}
	h, m := 0, 0
	for _, c := range parts[0] {
		h = h*10 + int(c-'0')
	}
	for _, c := range parts[1] {
		m = m*10 + int(c-'0')
	}
	return h*60 + m
}
