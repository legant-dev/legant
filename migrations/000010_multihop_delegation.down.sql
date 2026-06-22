DROP INDEX IF EXISTS idx_delegation_parent;
ALTER TABLE delegation_chains DROP COLUMN IF EXISTS depth;
ALTER TABLE delegation_chains DROP COLUMN IF EXISTS parent_delegation_id;
ALTER TABLE delegation_chains DROP COLUMN IF EXISTS delegator_type;
-- Restore the user FK (round-trips on a fresh schema; agent-delegator rows would
-- have to be cleared first in a populated database).
ALTER TABLE delegation_chains
    ADD CONSTRAINT delegation_chains_delegator_id_fkey FOREIGN KEY (delegator_id) REFERENCES users(id);
