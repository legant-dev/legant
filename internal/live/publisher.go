package live

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Channel is the Postgres NOTIFY channel that carries live events between
// processes (the server, the gateway, and every replica) and is consumed by the
// server's Listen loop.
const Channel = "legant_live"

// Publisher broadcasts events to the live console across processes via Postgres
// NOTIFY. It is the single emit path used by the token-exchange mint, the
// delegation revoker, the revocation store, and the MCP gateway — so one feed
// shows activity from every process and replica.
//
// Publish is non-blocking and best-effort: it enqueues to a bounded buffer
// drained by a background worker and drops events if the buffer is full, so a
// busy or stalled feed never adds latency to a mint or a tool call. nil-safe.
type Publisher struct {
	pool *pgxpool.Pool
	q    chan Event
}

// NewPublisher starts a background worker that drains queued events to Postgres
// NOTIFY. The worker stops when ctx is cancelled.
func NewPublisher(ctx context.Context, pool *pgxpool.Pool) *Publisher {
	p := &Publisher{pool: pool, q: make(chan Event, 512)}
	go p.run(ctx)
	return p
}

// Publish enqueues an event for broadcast. It never blocks: if the buffer is
// full the event is dropped.
func (p *Publisher) Publish(e Event) {
	if p == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	select {
	case p.q <- e:
	default:
	}
}

func (p *Publisher) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-p.q:
			b, err := json.Marshal(e)
			if err != nil {
				continue
			}
			// pg_notify caps the payload at 8000 bytes; our events are tiny.
			ec, cancel := context.WithTimeout(ctx, 3*time.Second)
			_, _ = p.pool.Exec(ec, "SELECT pg_notify($1, $2)", Channel, string(b))
			cancel()
		}
	}
}
