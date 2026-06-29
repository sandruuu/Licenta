package transport

import (
	"net"
	"net/http"
	"strings"
)

func clientIPFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	for _, header := range []string{"CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"} {
		if ip := firstValidIP(r.Header.Get(header)); ip != "" {
			return ip
		}
	}
	return firstValidIP(r.RemoteAddr)
}

func firstValidIP(raw string) string {
	for _, part := range strings.Split(raw, ",") {
		candidate := strings.TrimSpace(part)
		if candidate == "" {
			continue
		}
		if host, _, err := net.SplitHostPort(candidate); err == nil {
			candidate = host
		}
		candidate = strings.Trim(candidate, "[]")
		if ip := net.ParseIP(candidate); ip != nil {
			return ip.String()
		}
	}
	return ""
}
