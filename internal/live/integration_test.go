package live_test

import (
	"context"
	"testing"
	"time"

	"github.com/legant-dev/legant/internal/live"
	"github.com/legant-dev/legant/internal/testsupport"
)

// TestPublishListenRoundTrip proves the cross-process bridge: an event Published
// (Postgres NOTIFY) is received by Listen and fanned out to a hub subscriber.
func TestPublishListenRoundTrip(t *testing.T) {
	pool := testsupport.DB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hub := live.NewHub(50)
	go live.Listen(ctx, pool, hub)

	sub, stop := hub.Subscribe(16)
	defer stop()

	pub := live.NewPublisher(ctx, pool)
	// Give the listener a moment to LISTEN before publishing (it acquires a
	// dedicated connection asynchronously).
	deadline := time.Now().Add(5 * time.Second)
	var got live.Event
	for time.Now().Before(deadline) {
		pub.Publish(live.Event{Type: "mint", Decision: "MINT", Actor: "agent:x", Provenance: "user:a → agent:x"})
		select {
		case got = <-sub:
			if got.Type == "mint" && got.Provenance == "user:a → agent:x" {
				return // success
			}
		case <-time.After(150 * time.Millisecond):
		}
	}
	t.Fatalf("did not receive the published event through NOTIFY/LISTEN within the deadline; last=%+v", got)
}

// TestSnapshotActiveGraph builds a small delegation graph and asserts Snapshot
// returns only the active edges, with user/agent labels and the parent link.
func TestSnapshotActiveGraph(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()

	var userID, agentID, subAgentID string
	if err := pool.QueryRow(ctx, `INSERT INTO users (email,status) VALUES ('graph@x.com','active') RETURNING id::text`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO agents (name,type) VALUES ('assistant','ai_agent') RETURNING id::text`).Scan(&agentID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO agents (name,type) VALUES ('deal-finder','ai_agent') RETURNING id::text`).Scan(&subAgentID); err != nil {
		t.Fatal(err)
	}

	// Root delegation user -> assistant (active), and a re-delegation assistant ->
	// deal-finder (active), plus a revoked one that must NOT appear.
	var rootID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO delegation_chains (delegator_type, delegator_id, delegatee_agent_id, scopes, depth, active)
		 VALUES ('user',$1,$2,'{x}',0,true) RETURNING id::text`, userID, agentID).Scan(&rootID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO delegation_chains (delegator_type, delegator_id, delegatee_agent_id, scopes, depth, active, parent_delegation_id)
		 VALUES ('agent',$1,$2,'{x}',1,true,$3)`, agentID, subAgentID, rootID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO delegation_chains (delegator_type, delegator_id, delegatee_agent_id, scopes, depth, active)
		 VALUES ('user',$1,$2,'{x}',0,false)`, userID, subAgentID); err != nil {
		t.Fatal(err)
	}

	g, err := live.Snapshot(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Edges) != 2 {
		t.Fatalf("expected 2 active edges, got %d", len(g.Edges))
	}
	// Labels resolved from users.email / agents.name.
	labels := map[string]string{}
	for _, n := range g.Nodes {
		labels[n.ID] = n.Label
	}
	if labels["user:"+userID] != "user:graph@x.com" {
		t.Errorf("user node should be labeled by email, got %q", labels["user:"+userID])
	}
	if labels["agent:"+agentID] != "agent:assistant" {
		t.Errorf("agent node should be labeled by name, got %q", labels["agent:"+agentID])
	}
	// The re-delegation edge carries its parent (the root) and depth 1.
	var foundChild bool
	for _, e := range g.Edges {
		if e.Depth == 1 {
			foundChild = true
			if e.Parent != rootID {
				t.Errorf("child edge parent should be the root, got %q", e.Parent)
			}
			if e.From != "agent:"+agentID || e.To != "agent:"+subAgentID {
				t.Errorf("child edge endpoints wrong: %s -> %s", e.From, e.To)
			}
		}
	}
	if !foundChild {
		t.Error("expected the depth-1 re-delegation edge")
	}
}
