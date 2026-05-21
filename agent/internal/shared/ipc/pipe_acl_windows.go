//go:build windows

package ipc

import (
	"fmt"
	"strings"
)

const (
	pipeOwnerACL       = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
	interactiveUserACE = "(A;;GRGW;;;IU)"
)

func PipeSecurityDescriptor(authorizedUserSID string) (string, error) {
	userSID := strings.TrimSpace(authorizedUserSID)
	if userSID == "" {
		return pipeOwnerACL + interactiveUserACE, nil
	}
	if !strings.HasPrefix(userSID, "S-1-") {
		return "", fmt.Errorf("invalid Windows user SID %q", userSID)
	}
	return pipeOwnerACL + "(A;;GRGW;;;" + userSID + ")", nil
}
