package ipc

import (
	"fmt"
	"strings"
)

const pipeOwnerACL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"

func PipeSecurityDescriptor(enrolledUserSID string) (string, error) {
	userSID := strings.TrimSpace(enrolledUserSID)
	if userSID == "" {
		return pipeOwnerACL, nil
	}
	if !strings.HasPrefix(userSID, "S-1-") {
		return "", fmt.Errorf("invalid Windows user SID %q", userSID)
	}
	return pipeOwnerACL + "(A;;GRGW;;;" + userSID + ")", nil
}

func PipePath() string {
	return PipeName
}
