DROP INDEX IF EXISTS idx_audit_org;
DROP INDEX IF EXISTS idx_clients_org;
ALTER TABLE oauth2_clients DROP COLUMN IF EXISTS org_id;
DROP TABLE IF EXISTS sso_connections;
DROP TABLE IF EXISTS org_members;
DROP TABLE IF EXISTS orgs;
