-- Every composite (sub/act) delegation token minted by the token-exchange
-- endpoint is recorded here by its jti, so a self-contained JWT can still be
-- revoked before it expires.
CREATE TABLE exchanged_tokens (
    jti           TEXT PRIMARY KEY,
    delegation_id UUID REFERENCES delegation_chains(id) ON DELETE SET NULL,
    subject       TEXT NOT NULL,
    agent_id      UUID REFERENCES agents(id) ON DELETE CASCADE,
    actor_chain   TEXT[] NOT NULL DEFAULT '{}',
    audience      TEXT NOT NULL,
    scopes        TEXT[] NOT NULL DEFAULT '{}',
    issued_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL,
    revoked_at    TIMESTAMPTZ
);
CREATE INDEX idx_exchanged_tokens_delegation ON exchanged_tokens(delegation_id);
CREATE INDEX idx_exchanged_tokens_agent ON exchanged_tokens(agent_id);
CREATE INDEX idx_exchanged_tokens_expiry ON exchanged_tokens(expires_at);

-- Provenance columns so the audit trail records exactly who acted for whom.
ALTER TABLE audit_events ADD COLUMN on_behalf_of_sub TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN actor_chain TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE audit_events ADD COLUMN delegation_id UUID;
ALTER TABLE audit_events ADD COLUMN grant_jti TEXT NOT NULL DEFAULT '';
