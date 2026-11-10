package grantcheck

import "time"

// SetMinForced sets the shortest time between two reads of a namespace's
// heads that bypass the TTL (forcedState; tests).
func (ch *Checker) SetMinForced(d time.Duration) {
	ch.mu.Lock()
	ch.minForced = d
	ch.mu.Unlock()
}
