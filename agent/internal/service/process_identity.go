package service

import (
	"os"
	"os/user"
	"strings"
)

type processIdentity struct {
	PID      int
	Username string
	UserSID  string
}

func currentProcessIdentity() processIdentity {
	identity := processIdentity{PID: os.Getpid()}
	currentUser, err := user.Current()
	if err != nil || currentUser == nil {
		return identity
	}
	identity.Username = strings.TrimSpace(currentUser.Username)
	identity.UserSID = strings.TrimSpace(currentUser.Uid)
	return identity
}
