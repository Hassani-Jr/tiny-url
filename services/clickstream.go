package services

import (
	"sync"

	"tiny-url/models"
)

// ClickStream is an in-process pub-sub used by the redirect handler to
// fan out click events to any open SSE subscribers. It is intentionally
// simple — process-local, no replay buffer, no cross-instance routing.
//
// Cross-instance scenarios (multiple replicas behind a load balancer)
// would need an external bus (Redis Pub/Sub, NATS, etc.) so a click
// served by replica A reaches a SSE listener attached to replica B. That
// is left for operators who actually deploy multi-replica.
//
// Slow subscribers do NOT block publishers: the per-channel buffer is
// small, and a full buffer drops the event. This trades completeness
// for liveness — a hung browser tab cannot stall the redirect path.
type ClickStream struct {
	mu   sync.RWMutex
	subs map[string]map[*Subscription]struct{}
}

// Subscription is the receive-side of a ClickStream registration. The
// SSE handler typically does:
//
//	sub := stream.Subscribe(code)
//	defer sub.Close()
//	for ev := range sub.C() { ... }
//
// Close removes the subscription and closes the channel; it is safe to
// call multiple times. Internally it holds a per-subscription mutex so
// that an in-flight Publish on one goroutine cannot panic on a "send to
// closed channel" when Close fires from another goroutine.
type Subscription struct {
	code   string
	ch     chan models.ClickEvent
	stream *ClickStream

	mu     sync.Mutex
	closed bool
}

func (s *Subscription) C() <-chan models.ClickEvent { return s.ch }

func (s *Subscription) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.ch)
	s.mu.Unlock()
	s.stream.unsubscribe(s)
}

// trySend non-blocking-publishes ev under the subscription mutex. Returns
// silently if the subscription has been closed (lost race with Close) or
// if the buffer is full (slow consumer). Holding the mutex during the
// non-blocking send is fine — the select{default} ensures we never wait.
func (s *Subscription) trySend(ev models.ClickEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	select {
	case s.ch <- ev:
	default:
	}
}

func NewClickStream() *ClickStream {
	return &ClickStream{subs: make(map[string]map[*Subscription]struct{})}
}

// Subscribe registers a new subscriber for code. The returned Subscription
// receives every Publish targeting this code until Close is called.
func (s *ClickStream) Subscribe(code string) *Subscription {
	sub := &Subscription{
		code:   code,
		ch:     make(chan models.ClickEvent, 8),
		stream: s,
	}
	s.mu.Lock()
	if s.subs[code] == nil {
		s.subs[code] = make(map[*Subscription]struct{})
	}
	s.subs[code][sub] = struct{}{}
	s.mu.Unlock()
	return sub
}

// unsubscribe removes sub from the registry. Channel closing is owned by
// Subscription.Close (under its own mutex) so we don't need to do it here.
func (s *ClickStream) unsubscribe(sub *Subscription) {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := s.subs[sub.code]
	delete(set, sub)
	if len(set) == 0 {
		delete(s.subs, sub.code)
	}
}

// Publish sends ev to every current subscriber for code. Non-blocking:
// a full subscriber buffer drops the event for that subscriber only.
// SSE is best-effort presentation; the canonical event log lives in
// click_events, which RecordClick has already written by the time we
// call Publish.
func (s *ClickStream) Publish(code string, ev models.ClickEvent) {
	s.mu.RLock()
	set := s.subs[code]
	// Snapshot under the read lock so we don't hold it during sends.
	subs := make([]*Subscription, 0, len(set))
	for sub := range set {
		subs = append(subs, sub)
	}
	s.mu.RUnlock()
	for _, sub := range subs {
		// trySend handles the close-race + full-buffer case internally.
		sub.trySend(ev)
	}
}

// SubscriberCount is exposed for tests and operator inspection.
func (s *ClickStream) SubscriberCount(code string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.subs[code])
}
