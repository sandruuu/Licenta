package store

import "time"

// StartAutoSave runs periodic maintenance for persistent store data.
func (s *Store) StartAutoSave(interval time.Duration, stopChan <-chan struct{}) {
	if interval <= 0 {
		interval = time.Minute
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				s.CleanExpiredRevokedTokens()
			}
		}
	}()
}
