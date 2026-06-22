-- Initial access tokens that gate RFC 7591 dynamic client registration, so the
-- registration endpoint cannot be used for open/abusive client creation.
CREATE TABLE dcr_registration_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash  TEXT NOT NULL UNIQUE,
    org_id      UUID REFERENCES orgs(id),
    max_uses    INT NOT NULL DEFAULT 1,
    used_count  INT NOT NULL DEFAULT 0,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
