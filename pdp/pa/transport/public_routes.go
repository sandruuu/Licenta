package transport

import (
	"net/url"
	"strings"
)

const (
	publicEnrollPathPrefix = "/enroll/"
	publicSignInPathPrefix = "/sign-in/"
	publicStepUpPathPrefix = "/verify/"
	publicStepUpAssetPath  = "/verify/assets/stepup.js"
)

func publicSignInURL(origin, sessionID string) string {
	return strings.TrimRight(strings.TrimSpace(origin), "/") + publicSignInPathPrefix + url.PathEscape(strings.TrimSpace(sessionID))
}

func publicPathID(path, prefix string) string {
	path = strings.TrimSpace(path)
	if strings.HasPrefix(path, prefix) {
		return strings.Trim(strings.TrimPrefix(path, prefix), "/")
	}
	return ""
}

func isPublicEnrollOrSignInPath(path string) bool {
	return pathHasAnyPrefix(path, publicEnrollPathPrefix, publicSignInPathPrefix)
}

func isPublicStepUpPath(path string) bool {
	return pathHasAnyPrefix(path, publicStepUpPathPrefix)
}

func pathHasAnyPrefix(path string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if path == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
