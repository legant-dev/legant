// Package live is an in-process pub/sub hub for real-time activity events that
// feed the /admin/live console: every gateway tool-call decision, token mint,
// and revocation is published here and fanned out to connected SSE clients.
//
// The hub is deliberately best-effort: publishing never blocks the request path,
// and a slow consumer drops events rather than applying backpressure. It is also
// nil-safe — emit sites may hold a nil *Hub when the live console is disabled,
// and calling Publish on it is a no-op.
package live

import (
	"sync"
	"time"
)

// Event is a single real-time activity record. Only the fields relevant to the
// event Type are populated; the rest are omitted from the JSON.
type Event struct {
	Type       string    `json:"type"`                 // decision | mint | revoke
	Time       time.Time `json:"ts"`                   // when it happened
	Decision   string    `json:"decision,omitempty"`   // ALLOW | DENY | REVOKE | MINT
	Subject    string    `json:"subject,omitempty"`    // root user, e.g. "user:alice"
	Actor      string    `json:"actor,omitempty"`      // acting agent, e.g. "agent:conductor"
	Provenance string    `json:"provenance,omitempty"` // "user:alice → agent:x → agent:y"
	Tool       string    `json:"tool,omitempty"`       // tool/method on a decision
	Upstream   string    `json:"upstream,omitempty"`   // gateway upstream slug / audience
	Reason     string    `json:"reason,omitempty"`     // why a decision was DENY
	Delegation string    `json:"delegation,omitempty"` // delegation id (mint/revoke)
	Count      int       `json:"count,omitempty"`      // e.g. revoked-subtree size
}

// Hub fans Events out to all current subscribers and keeps a small replay ring
// so a newly-connected console can render recent history immediately.
type Hub struct {
	mu      sync.Mutex
	subs    map[chan Event]struct{}
	ring    []Event
	ringCap int
}

// NewHub returns a hub that retains the last ringCap events for replay.
func NewHub(ringCap int) *Hub {
	if ringCap <= 0 {
		ringCap = 200
	}
	return &Hub{subs: map[chan Event]struct{}{}, ringCap: ringCap}
}

// Publish records the event in the replay ring and fans it out to every
// subscriber without blocking. A subscriber whose buffer is full drops the
// event — the console is observability, never a source of backpressure on the
// request path. Publish is nil-safe.
func (h *Hub) Publish(e Event) {
	if h == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	h.mu.Lock()
	h.ring = append(h.ring, e)
	if len(h.ring) > h.ringCap {
		h.ring = h.ring[len(h.ring)-h.ringCap:]
	}
	for ch := range h.subs {
		select {
		case ch <- e:
		default:
		}
	}
	h.mu.Unlock()
}

// Subscribe registers a new subscriber and returns its event channel plus an
// unsubscribe function. The channel is buffered; events arriving while it is
// full are dropped for that subscriber. The unsubscribe function is idempotent
// and closes the channel.
func (h *Hub) Subscribe(buffer int) (<-chan Event, func()) {
	if buffer <= 0 {
		buffer = 64
	}
	ch := make(chan Event, buffer)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.subs, ch)
			close(ch)
			h.mu.Unlock()
		})
	}
}

// Recent returns a copy of the replay ring, oldest first.
func (h *Hub) Recent() []Event {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]Event, len(h.ring))
	copy(out, h.ring)
	return out
}

// Subscribers reports the number of currently-connected subscribers.
func (h *Hub) Subscribers() int {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}
