ALTER TABLE audit_events DROP COLUMN IF EXISTS grant_jti;
ALTER TABLE audit_events DROP COLUMN IF EXISTS delegation_id;
ALTER TABLE audit_events DROP COLUMN IF EXISTS actor_chain;
ALTER TABLE audit_events DROP COLUMN IF EXISTS on_behalf_of_sub;
DROP TABLE IF EXISTS exchanged_tokens;
