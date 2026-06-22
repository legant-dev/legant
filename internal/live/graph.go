package live

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Node is a principal in the authority graph: a user or an agent.
type Node struct {
	ID    string `json:"id"`    // namespaced stable id: "user:<uuid>" / "agent:<uuid>"
	Label string `json:"label"` // display: "user:alice" / "agent:assistant"
	Kind  string `json:"kind"`  // "user" | "agent"
}

// Edge is one active delegation: delegator --grants--> delegatee agent.
type Edge struct {
	ID     string `json:"id"`               // delegation_chains.id
	Parent string `json:"parent,omitempty"` // parent delegation id (re-delegation)
	From   string `json:"from"`             // delegator node id
	To     string `json:"to"`               // delegatee node id
	Depth  int    `json:"depth"`
}

// Graph is a snapshot of the current active authority graph.
type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// Snapshot returns the current active delegation graph: every delegation that is
// active and unexpired, as nodes (users + agents) and edges (delegations). This
// is the exact active-ness predicate the delegation service uses everywhere:
// active = true AND (expires_at IS NULL OR expires_at > now()).
func Snapshot(ctx context.Context, pool *pgxpool.Pool) (*Graph, error) {
	rows, err := pool.Query(ctx, `
		SELECT d.id::text,
		       coalesce(d.parent_delegation_id::text, ''),
		       d.depth,
		       d.delegator_type,
		       d.delegator_id::text,
		       CASE d.delegator_type
		           WHEN 'user'  THEN 'user:'  || coalesce(u.email, d.delegator_id::text)
		           WHEN 'agent' THEN 'agent:' || coalesce(da.name, d.delegator_id::text)
		           ELSE d.delegator_type || ':' || d.delegator_id::text
		       END,
		       d.delegatee_agent_id::text,
		       'agent:' || coalesce(a.name, d.delegatee_agent_id::text)
		FROM delegation_chains d
		JOIN agents a       ON a.id = d.delegatee_agent_id
		LEFT JOIN users  u  ON d.delegator_type = 'user'  AND u.id  = d.delegator_id
		LEFT JOIN agents da ON d.delegator_type = 'agent' AND da.id = d.delegator_id
		WHERE d.active = true
		  AND (d.expires_at IS NULL OR d.expires_at > now())
		ORDER BY d.depth, d.created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	g := &Graph{Nodes: []Node{}, Edges: []Edge{}}
	seen := map[string]bool{}
	addNode := func(id, label, kind string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		g.Nodes = append(g.Nodes, Node{ID: id, Label: label, Kind: kind})
	}

	for rows.Next() {
		var id, parent string
		var depth int
		var dtype, did, fromLabel, toAgentID, toLabel string
		if err := rows.Scan(&id, &parent, &depth, &dtype, &did, &fromLabel, &toAgentID, &toLabel); err != nil {
			return nil, err
		}
		fromID := dtype + ":" + did
		toID := "agent:" + toAgentID
		addNode(fromID, fromLabel, dtype)
		addNode(toID, toLabel, "agent")
		g.Edges = append(g.Edges, Edge{ID: id, Parent: parent, From: fromID, To: toID, Depth: depth})
	}
	return g, rows.Err()
}
