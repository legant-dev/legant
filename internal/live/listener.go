package live

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// validTypes / validDecisions bound what the console will render. The NOTIFY
// channel is NOT a trusted source — anyone with database access can publish to
// it — so events are validated here before they ever reach a subscriber.
var validTypes = map[string]bool{"decision": true, "mint": true, "revoke": true}
var validDecisions = map[string]bool{"": true, "ALLOW": true, "DENY": true, "REVOKE": true, "MINT": true}

const maxFieldLen = 512

func valid(e Event) bool {
	if !validTypes[e.Type] || !validDecisions[e.Decision] {
		return false
	}
	for _, s := range []string{e.Subject, e.Actor, e.Provenance, e.Tool, e.Upstream, e.Reason, e.Delegation} {
		if len(s) > maxFieldLen {
			return false
		}
	}
	return true
}

// Listen holds a dedicated Postgres connection, LISTENs on the live channel, and
// republishes every received event into the hub for local SSE subscribers. It
// reconnects with capped exponential backoff until ctx is cancelled, so a
// transient database blip doesn't permanently silence the console. Run it in a
// goroutine for the lifetime of the process.
func Listen(ctx context.Context, pool *pgxpool.Pool, hub *Hub) {
	backoff := time.Second
	for ctx.Err() == nil {
		// Reset backoff once a healthy connection is established, so an isolated
		// blip after a long stable period doesn't inherit a saturated delay.
		err := listenOnce(ctx, pool, hub, func() { backoff = time.Second })
		if ctx.Err() != nil {
			return
		}
		slog.Warn("live listener disconnected; reconnecting", "err", err, "in", backoff)
		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func listenOnce(ctx context.Context, pool *pgxpool.Pool, hub *Hub, onConnect func()) error {
	pc, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	// Hijack removes the connection from the pool so a long-lived LISTEN never
	// pollutes a pooled connection; we own it and close it on return.
	conn := pc.Hijack()
	defer conn.Close(context.Background())

	if _, err := conn.Exec(ctx, "LISTEN "+Channel); err != nil {
		return err
	}
	onConnect()
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		var e Event
		if json.Unmarshal([]byte(n.Payload), &e) == nil && valid(e) {
			hub.Publish(e)
		}
	}
}
