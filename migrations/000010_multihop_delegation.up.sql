-- Multi-hop delegation: an agent can re-delegate an attenuated slice of its
-- authority to a sub-agent, so the delegator is no longer always a user.
ALTER TABLE delegation_chains DROP CONSTRAINT IF EXISTS delegation_chains_delegator_id_fkey;
ALTER TABLE delegation_chains ADD COLUMN delegator_type TEXT NOT NULL DEFAULT 'user'
    CHECK (delegator_type IN ('user', 'agent'));
ALTER TABLE delegation_chains ADD COLUMN parent_delegation_id UUID REFERENCES delegation_chains(id) ON DELETE CASCADE;
ALTER TABLE delegation_chains ADD COLUMN depth INT NOT NULL DEFAULT 0;
CREATE INDEX idx_delegation_parent ON delegation_chains(parent_delegation_id);
