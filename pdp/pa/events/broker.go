// Package events provides an in-memory topic-based pub/sub broker used by
// the PA control plane to fan out internal state-change events.
//
// Design goals:
//   - Lock contention bounded by topic count, not subscriber count.
//   - Slow subscribers MUST NOT block the publisher: each subscriber owns a
//     bounded buffered channel; if it fills the broker drops the oldest
//     event for that subscriber and increments a counter so operators can
//     spot mis-sized buffers.
//   - The broker is single-process. A future multi-PDP HA deployment
//     would replace this with NATS / Redis pub/sub; the public surface is
//     intentionally narrow so that swap is straightforward.
package events

import (
	"sync"
	"sync/atomic"
	"time"
)

// Event is the unit of fan-out. The Type names should be stable strings
// since they are part of the wire protocol consumed by long-lived clients.
type Event struct {
	Type    string      `json:"type"`              // e.g. "revocation", "policy.updated", "session.deleted"
	Time    time.Time   `json:"time"`              // server-side publish timestamp
	Payload interface{} `json:"payload,omitempty"` // event-specific JSON-serialisable body
}

// Subscription is what a subscriber receives. C is closed when the
// subscription is cancelled (Unsubscribe or broker shutdown).
type Subscription struct {
	C       <-chan Event
	id      uint64
	topics  []string
	send    chan Event
	closed  atomic.Bool
	dropped atomic.Uint64
}

// Dropped returns the number of events dropped for this subscription due
// to a full buffer. Useful for operators to detect undersized clients.
func (s *Subscription) Dropped() uint64 { return s.dropped.Load() }

// Broker is a topic-based pub/sub fanout. Zero value is not usable —
// always construct via NewBroker.
type Broker struct {
	mu       sync.RWMutex
	subs     map[string]map[uint64]*Subscription // topic -> id -> sub
	nextID   atomic.Uint64
	bufSize  int
	shutdown atomic.Bool
}

// NewBroker returns an empty broker. bufSize is the per-subscriber channel
// capacity (recommended 32–128); too small causes drops on bursts, too
// large wastes memory.
func NewBroker(bufSize int) *Broker {
	if bufSize <= 0 {
		bufSize = 64
	}
	return &Broker{
		subs:    make(map[string]map[uint64]*Subscription),
		bufSize: bufSize,
	}
}

// Subscribe registers a subscriber for the given topics. The returned
// Subscription's channel will receive events published to any of those
// topics until Unsubscribe (or Shutdown) is called.
func (b *Broker) Subscribe(topics ...string) *Subscription {
	id := b.nextID.Add(1)
	ch := make(chan Event, b.bufSize)
	sub := &Subscription{
		C:      ch,
		id:     id,
		topics: append([]string(nil), topics...),
		send:   ch,
	}

	b.mu.Lock()
	for _, t := range topics {
		m, ok := b.subs[t]
		if !ok {
			m = make(map[uint64]*Subscription)
			b.subs[t] = m
		}
		m[id] = sub
	}
	b.mu.Unlock()
	return sub
}

// Unsubscribe removes the subscriber and closes its channel. Safe to call
// multiple times.
func (b *Broker) Unsubscribe(sub *Subscription) {
	if sub == nil || !sub.closed.CompareAndSwap(false, true) {
		return
	}
	b.mu.Lock()
	for _, t := range sub.topics {
		if m, ok := b.subs[t]; ok {
			delete(m, sub.id)
			if len(m) == 0 {
				delete(b.subs, t)
			}
		}
	}
	b.mu.Unlock()
	close(sub.send)
}

// Publish fan-outs an event to every subscriber of topic. It never blocks:
// if a subscriber's buffer is full the oldest event for that subscriber is
// dropped (counted via Subscription.Dropped()) and the new event is enqueued.
func (b *Broker) Publish(topic string, evt Event) {
	if b.shutdown.Load() {
		return
	}
	if evt.Time.IsZero() {
		evt.Time = time.Now()
	}

	// Snapshot subscriber set under read lock so Publish is safe to call
	// concurrently with Subscribe / Unsubscribe.
	b.mu.RLock()
	m := b.subs[topic]
	if len(m) == 0 {
		b.mu.RUnlock()
		return
	}
	pending := make([]*Subscription, 0, len(m))
	for _, s := range m {
		pending = append(pending, s)
	}
	b.mu.RUnlock()

	for _, s := range pending {
		if s.closed.Load() {
			continue
		}
		select {
		case s.send <- evt:
		default:
			// Buffer full: drop oldest, then attempt enqueue. We accept a
			// best-effort drop here — if the channel is being concurrently
			// drained we may double-drop, but the drop counter is
			// monotonic so over-counting is bounded by races.
			select {
			case <-s.send:
				s.dropped.Add(1)
			default:
			}
			select {
			case s.send <- evt:
			default:
				s.dropped.Add(1)
			}
		}
	}
}

// Shutdown cancels all subscriptions and prevents further Publish calls
// from delivering. Safe to call once at process shutdown.
func (b *Broker) Shutdown() {
	if !b.shutdown.CompareAndSwap(false, true) {
		return
	}
	b.mu.Lock()
	subs := make([]*Subscription, 0)
	seen := make(map[uint64]bool)
	for _, m := range b.subs {
		for id, s := range m {
			if !seen[id] {
				seen[id] = true
				subs = append(subs, s)
			}
		}
	}
	b.subs = make(map[string]map[uint64]*Subscription)
	b.mu.Unlock()

	for _, s := range subs {
		if s.closed.CompareAndSwap(false, true) {
			close(s.send)
		}
	}
}

// Standard topic names referenced by handlers and long-lived event clients.
const (
	TopicRevocation       = "revocation"        // payload: {serial: "..."}
	TopicPolicyUpdated    = "policy.updated"    // payload: {} for internal state-change consumers
	TopicResourcesUpdated = "resources.updated" // payload: {resource_id?: "..."}
	TopicSessionDeleted   = "session.deleted"   // payload: {session_id: "..."}
	TopicHealthChanged    = "health.changed"    // payload: {device_id: "...", status: "..."}
)
