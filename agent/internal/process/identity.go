package process

import (
	"os"
	"os/user"
	"strings"
)

type Identity struct {
	PID      int    `json:"pid"`
	Username string `json:"username,omitempty"`
	UserSID  string `json:"user_sid,omitempty"`
}

func Current() Identity {
	identity := Identity{PID: os.Getpid()}
	currentUser, err := user.Current()
	if err != nil || currentUser == nil {
		return identity
	}
	identity.Username = strings.TrimSpace(currentUser.Username)
	identity.UserSID = strings.TrimSpace(currentUser.Uid)
	return identity
}
