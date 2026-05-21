package service

import (
	"os"
	"os/user"
	"strings"
	"time"
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

func (service *Service) State() State {
	service.mu.RLock()
	defer service.mu.RUnlock()
	return service.state
}

func (service *Service) setStartedAt(startedAt time.Time) {
	service.mu.Lock()
	service.startedAt = startedAt
	service.mu.Unlock()
}

func (service *Service) transition(next State) {
	service.mu.Lock()
	service.state = next
	service.mu.Unlock()
	service.logger.Info("TrustAgent service state changed", "state", next)
}
