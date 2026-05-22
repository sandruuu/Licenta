package service

import "time"

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
