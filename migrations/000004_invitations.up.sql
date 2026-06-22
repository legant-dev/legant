CREATE TABLE org_invitations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member')),
    token       TEXT NOT NULL UNIQUE,
    status      TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'revoked', 'expired')),
    inviter_id  UUID REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '7 days')
);
CREATE INDEX idx_invitations_org ON org_invitations(org_id);
CREATE INDEX idx_invitations_token ON org_invitations(token);
CREATE INDEX idx_invitations_email ON org_invitations(email);
