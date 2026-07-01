package events

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"pdp/runtime/redisstate"
)

type Event struct {
	Type    string      `json:"type"`
	Time    time.Time   `json:"time"`
	Payload interface{} `json:"payload,omitempty"`
}

type Subscription struct {
	C       <-chan Event
	id      uint64
	topics  []string
	send    chan Event
	closed  atomic.Bool
	dropped atomic.Uint64
}

func (s *Subscription) Dropped() uint64 { return s.dropped.Load() }

type Broker struct {
	mu       sync.RWMutex
	subs     map[string]map[uint64]*Subscription
	nextID   atomic.Uint64
	bufSize  int
	shutdown atomic.Bool
	runtime  *redisstate.Client
	cancel   context.CancelFunc
	closeSub func() error
}

func NewBroker(runtimeState *redisstate.Client, bufSize int) *Broker {
	if bufSize <= 0 {
		bufSize = 64
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &Broker{
		subs:    make(map[string]map[uint64]*Subscription),
		bufSize: bufSize,
		runtime: runtimeState,
		cancel:  cancel,
	}
	if runtimeState == nil {
		log.Printf("[EVENTS] Redis runtime state unavailable; event broker disabled")
		return b
	}
	messages, closeSub, err := runtimeState.SubscribeEvents(ctx, standardTopics()...)
	if err != nil {
		log.Printf("[EVENTS] Redis subscribe failed: %v", err)
		return b
	}
	b.closeSub = closeSub
	go b.listen(messages)
	return b
}

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

func (b *Broker) Publish(topic string, evt Event) {
	if b == nil || b.shutdown.Load() {
		return
	}
	if evt.Time.IsZero() {
		evt.Time = time.Now().UTC()
	}
	if evt.Type == "" {
		evt.Type = topic
	}
	if b.runtime == nil {
		b.deliver(topic, evt)
		return
	}
	raw, err := json.Marshal(evt)
	if err != nil {
		log.Printf("[EVENTS] marshal topic=%s: %v", topic, err)
		return
	}
	if err := b.runtime.PublishEvent(topic, raw); err != nil {
		log.Printf("[EVENTS] publish topic=%s: %v", topic, err)
		b.deliver(topic, evt)
	}
}

func (b *Broker) listen(messages <-chan redisstate.PubSubMessage) {
	for msg := range messages {
		if b.shutdown.Load() {
			return
		}
		var evt Event
		if err := json.Unmarshal(msg.Payload, &evt); err != nil {
			log.Printf("[EVENTS] decode topic=%s: %v", msg.Topic, err)
			continue
		}
		if evt.Type == "" {
			evt.Type = msg.Topic
		}
		b.deliver(msg.Topic, evt)
	}
}

func (b *Broker) deliver(topic string, evt Event) {
	if b.shutdown.Load() {
		return
	}
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

func (b *Broker) Shutdown() {
	if b == nil || !b.shutdown.CompareAndSwap(false, true) {
		return
	}
	if b.cancel != nil {
		b.cancel()
	}
	if b.closeSub != nil {
		_ = b.closeSub()
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

const (
	TopicRevocation               = "revocation"
	TopicPolicyUpdated            = "policy.updated"
	TopicResourcesUpdated         = "resources.updated"
	TopicSessionDeleted           = "session.deleted"
	TopicStepUpCompleted          = "step_up.completed"
	TopicHealthChanged            = "health.changed"
	TopicDeviceRevoked            = "device.revoked"
	TopicGatewayRevoked           = "gateway.revoked"
	TopicEnrollmentSessionUpdated = "enrollment.session.updated"
	TopicAgentSessionUpdated      = "agent.session.updated"
)

func standardTopics() []string {
	return []string{
		TopicRevocation,
		TopicPolicyUpdated,
		TopicResourcesUpdated,
		TopicSessionDeleted,
		TopicStepUpCompleted,
		TopicHealthChanged,
		TopicDeviceRevoked,
		TopicGatewayRevoked,
		TopicEnrollmentSessionUpdated,
		TopicAgentSessionUpdated,
	}
}
