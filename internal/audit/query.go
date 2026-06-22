package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Event is a read-model row of the audit trail, including the full delegation
// provenance (on_behalf_of_sub + actor_chain) of who acted for whom.
type Event struct {
	ID           int64           `json:"id"`
	Seq          *int64          `json:"seq,omitempty"`
	ActorType    string          `json:"actor_type"`
	ActorID      string          `json:"actor_id,omitempty"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type,omitempty"`
	ResourceID   string          `json:"resource_id,omitempty"`
	OnBehalfOf   string          `json:"on_behalf_of_sub,omitempty"`
	ActorChain   []string        `json:"actor_chain,omitempty"`
	DelegationID *string         `json:"delegation_id,omitempty"`
	GrantJTI     string          `json:"grant_jti,omitempty"`
	OrgID        *string         `json:"org_id,omitempty"`
	Metadata     json.RawMessage `json:"metadata,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
}

// Filter narrows an audit query. Empty/zero fields are not applied.
type Filter struct {
	ActorType    string
	ActorID      string
	Action       string
	OnBehalfOf   string
	DelegationID string
	GrantJTI     string
	Since        *time.Time
	Until        *time.Time
	Limit        int
	Offset       int
}

const maxAuditPage = 200

// Query returns audit events matching the filter (newest first) and the total
// count of matches (before pagination). All filter values are bound as
// parameters — never interpolated — so the query is injection-safe.
func Query(ctx context.Context, pool *pgxpool.Pool, f Filter) ([]Event, int64, error) {
	conds := []string{"true"}
	var args []any
	eq := func(col, val string, cast string) {
		if val == "" {
			return
		}
		args = append(args, val)
		conds = append(conds, fmt.Sprintf("%s%s = $%d", col, cast, len(args)))
	}
	eq("actor_type", f.ActorType, "")
	eq("actor_id", f.ActorID, "")
	eq("action", f.Action, "")
	eq("on_behalf_of_sub", f.OnBehalfOf, "")
	eq("grant_jti", f.GrantJTI, "")
	eq("delegation_id", f.DelegationID, "::text")
	if f.Since != nil {
		args = append(args, *f.Since)
		conds = append(conds, fmt.Sprintf("created_at >= $%d", len(args)))
	}
	if f.Until != nil {
		args = append(args, *f.Until)
		conds = append(conds, fmt.Sprintf("created_at <= $%d", len(args)))
	}
	where := strings.Join(conds, " AND ")

	var total int64
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count audit events: %w", err)
	}

	limit := f.Limit
	if limit <= 0 || limit > maxAuditPage {
		limit = 50
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	pageArgs := append(append([]any(nil), args...), limit, offset)
	q := fmt.Sprintf(`
		SELECT id, seq, actor_type, actor_id, action, resource_type, resource_id,
		       on_behalf_of_sub, actor_chain, delegation_id::text, grant_jti, org_id::text, metadata, created_at
		FROM audit_events
		WHERE %s
		ORDER BY seq DESC NULLS LAST, id DESC
		LIMIT $%d OFFSET $%d`, where, len(args)+1, len(args)+2)

	rows, err := pool.Query(ctx, q, pageArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("query audit events: %w", err)
	}
	defer rows.Close()

	out := make([]Event, 0, limit)
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.Seq, &e.ActorType, &e.ActorID, &e.Action, &e.ResourceType,
			&e.ResourceID, &e.OnBehalfOf, &e.ActorChain, &e.DelegationID, &e.GrantJTI, &e.OrgID, &e.Metadata, &e.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("scan audit event: %w", err)
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}
