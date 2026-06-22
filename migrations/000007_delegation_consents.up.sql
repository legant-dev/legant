-- Consent receipts: a user's explicit, recorded approval to delegate a slice of
-- their authority to an agent. Every root delegation must reference one.
CREATE TABLE delegation_consents (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    agent_id    UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    org_id      UUID REFERENCES orgs(id),
    scopes      TEXT[] NOT NULL DEFAULT '{}',
    constraints JSONB NOT NULL DEFAULT '{}',
    resource    TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_delegation_consents_user ON delegation_consents(user_id);
CREATE INDEX idx_delegation_consents_agent ON delegation_consents(agent_id);

-- Tie each delegation to the consent that authorized it.
ALTER TABLE delegation_chains ADD COLUMN consent_id UUID REFERENCES delegation_consents(id);
