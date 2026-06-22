-- Superadmin flag for platform-wide administration (bootstrapped offline via
-- `legant admin grant-superadmin`).
ALTER TABLE users ADD COLUMN is_superadmin BOOLEAN NOT NULL DEFAULT false;

-- Tenant-scope delegations so they can be governed and listed per organization.
ALTER TABLE delegation_chains ADD COLUMN org_id UUID REFERENCES orgs(id);
CREATE INDEX idx_delegation_org ON delegation_chains(org_id);
