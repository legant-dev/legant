-- Organizations (tenants)
CREATE TABLE orgs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    parent_id   UUID REFERENCES orgs(id),
    settings    JSONB NOT NULL DEFAULT '{}',
    status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Organization Members
CREATE TABLE org_members (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, user_id)
);
CREATE INDEX idx_org_members_user ON org_members(user_id);

-- Per-tenant SSO Connections
CREATE TABLE sso_connections (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    provider    TEXT NOT NULL,
    config      JSONB NOT NULL,
    domain      TEXT NOT NULL DEFAULT '',
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX idx_sso_domain ON sso_connections(domain) WHERE domain != '';

-- Link OAuth2 clients to orgs
ALTER TABLE oauth2_clients ADD COLUMN org_id UUID REFERENCES orgs(id);
CREATE INDEX idx_clients_org ON oauth2_clients(org_id);

-- Add org_id index to audit_events
CREATE INDEX idx_audit_org ON audit_events(org_id);
