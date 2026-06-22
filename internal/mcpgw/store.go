package mcpgw

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"
)

// UpstreamStore is the DB-backed registry of MCP gateway upstreams. It lets an
// operator add/remove upstreams without redeploying the gateway; the gateway
// merges these with its static config and refreshes on a timer.
type UpstreamStore struct {
	pool *pgxpool.Pool
}

func NewUpstreamStore(pool *pgxpool.Pool) *UpstreamStore {
	return &UpstreamStore{pool: pool}
}

// List returns all registered upstreams.
func (s *UpstreamStore) List(ctx context.Context) ([]*Upstream, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT slug, inbound_audience, url, resource_id, tool_scopes FROM gateway_upstreams ORDER BY slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Upstream{}
	for rows.Next() {
		u := &Upstream{}
		var toolScopes []byte
		if err := rows.Scan(&u.Slug, &u.InboundAudience, &u.URL, &u.ResourceID, &toolScopes); err != nil {
			return nil, err
		}
		if len(toolScopes) > 0 {
			if err := json.Unmarshal(toolScopes, &u.ToolScopes); err != nil {
				return nil, err
			}
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// Upsert creates or replaces an upstream by slug.
func (s *UpstreamStore) Upsert(ctx context.Context, u *Upstream) error {
	scopes, err := json.Marshal(u.ToolScopes)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO gateway_upstreams (slug, inbound_audience, url, resource_id, tool_scopes)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (slug) DO UPDATE SET
		   inbound_audience = excluded.inbound_audience, url = excluded.url,
		   resource_id = excluded.resource_id, tool_scopes = excluded.tool_scopes,
		   updated_at = now()`,
		u.Slug, u.InboundAudience, u.URL, u.ResourceID, scopes)
	return err
}

// Delete removes an upstream by slug; returns whether a row was removed.
func (s *UpstreamStore) Delete(ctx context.Context, slug string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM gateway_upstreams WHERE slug = $1`, slug)
	return tag.RowsAffected() > 0, err
}
