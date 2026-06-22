-- Non-human identities (AI agents, service accounts)
CREATE TABLE agents (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID REFERENCES orgs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    type        TEXT NOT NULL DEFAULT 'service' CHECK (type IN ('service', 'ai_agent', 'mcp_server')),
    owner_id    UUID REFERENCES users(id),
    status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'revoked')),
    metadata    JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_agents_org ON agents(org_id);
CREATE INDEX idx_agents_owner ON agents(owner_id);

-- Agent tokens (long-lived, scoped)
CREATE TABLE agent_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL DEFAULT '',
    scopes          TEXT[] NOT NULL DEFAULT '{}',
    permissions     JSONB NOT NULL DEFAULT '{}',
    expires_at      TIMESTAMPTZ,
    last_used_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_agent_tokens_agent ON agent_tokens(agent_id);

-- Delegation chains: user delegates subset of permissions to an agent
CREATE TABLE delegation_chains (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    delegator_id        UUID NOT NULL REFERENCES users(id),
    delegatee_agent_id  UUID NOT NULL REFERENCES agents(id),
    scopes              TEXT[] NOT NULL DEFAULT '{}',
    constraints         JSONB NOT NULL DEFAULT '{}',
    active              BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ
);
CREATE INDEX idx_delegation_delegator ON delegation_chains(delegator_id);
CREATE INDEX idx_delegation_agent ON delegation_chains(delegatee_agent_id);

-- API Keys
CREATE TABLE api_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID REFERENCES orgs(id) ON DELETE CASCADE,
    owner_id    UUID,
    owner_type  TEXT NOT NULL DEFAULT 'user' CHECK (owner_type IN ('user', 'agent', 'org')),
    key_hash    TEXT NOT NULL UNIQUE,
    key_prefix  TEXT NOT NULL,
    name        TEXT NOT NULL,
    scopes      TEXT[] NOT NULL DEFAULT '{}',
    last_used_at TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_api_keys_org ON api_keys(org_id);
