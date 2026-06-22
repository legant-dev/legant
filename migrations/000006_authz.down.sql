DROP INDEX IF EXISTS idx_delegation_org;
ALTER TABLE delegation_chains DROP COLUMN IF EXISTS org_id;
ALTER TABLE users DROP COLUMN IF EXISTS is_superadmin;
