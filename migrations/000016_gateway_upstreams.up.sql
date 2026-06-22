-- DB-backed MCP gateway upstream registry, so upstreams can be added or removed
-- without redeploying the gateway. These are ADDITIVE to any upstreams declared in
-- static config; the gateway merges both and refreshes from this table on a timer.
-- inbound_audience is unique to preserve cross-upstream token isolation.
CREATE TABLE gateway_upstreams (
    slug             TEXT PRIMARY KEY,
    inbound_audience TEXT NOT NULL UNIQUE,
    url              TEXT NOT NULL,
    resource_id      TEXT NOT NULL,
    tool_scopes      JSONB NOT NULL DEFAULT '{}',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
