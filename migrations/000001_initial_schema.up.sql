-- Users
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT NOT NULL,
    email_verified  BOOLEAN NOT NULL DEFAULT FALSE,
    display_name    TEXT NOT NULL DEFAULT '',
    avatar_url      TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted')),
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (email)
);

-- Credentials (password, passkey, totp, recovery)
CREATE TABLE credentials (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type            TEXT NOT NULL CHECK (type IN ('password', 'passkey', 'totp', 'recovery')),
    data            BYTEA NOT NULL,
    label           TEXT NOT NULL DEFAULT '',
    last_used_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_credentials_user ON credentials(user_id);

-- Sessions
CREATE TABLE sessions (
    id              TEXT PRIMARY KEY,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip              INET,
    user_agent      TEXT NOT NULL DEFAULT '',
    data            JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_active_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

-- OAuth2 Clients
CREATE TABLE oauth2_clients (
    id                          TEXT PRIMARY KEY,
    secret_hash                 TEXT NOT NULL DEFAULT '',
    name                        TEXT NOT NULL,
    redirect_uris               TEXT[] NOT NULL DEFAULT '{}',
    grant_types                 TEXT[] NOT NULL DEFAULT '{authorization_code}',
    response_types              TEXT[] NOT NULL DEFAULT '{code}',
    scopes                      TEXT[] NOT NULL DEFAULT '{}',
    audience                    TEXT[] NOT NULL DEFAULT '{}',
    public                      BOOLEAN NOT NULL DEFAULT FALSE,
    token_endpoint_auth_method  TEXT NOT NULL DEFAULT 'client_secret_basic',
    metadata                    JSONB NOT NULL DEFAULT '{}',
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- OAuth2 Authorization Codes
CREATE TABLE oauth2_auth_codes (
    signature       TEXT PRIMARY KEY,
    request_id      TEXT NOT NULL,
    client_id       TEXT NOT NULL REFERENCES oauth2_clients(id),
    session_data    BYTEA NOT NULL,
    requested_at    TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    active          BOOLEAN NOT NULL DEFAULT TRUE
);

-- OAuth2 Access Tokens
CREATE TABLE oauth2_access_tokens (
    signature       TEXT PRIMARY KEY,
    request_id      TEXT NOT NULL,
    client_id       TEXT NOT NULL REFERENCES oauth2_clients(id),
    session_data    BYTEA NOT NULL,
    requested_at    TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    active          BOOLEAN NOT NULL DEFAULT TRUE
);

-- OAuth2 Refresh Tokens
CREATE TABLE oauth2_refresh_tokens (
    signature       TEXT PRIMARY KEY,
    request_id      TEXT NOT NULL,
    client_id       TEXT NOT NULL REFERENCES oauth2_clients(id),
    session_data    BYTEA NOT NULL,
    requested_at    TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    active          BOOLEAN NOT NULL DEFAULT TRUE
);

-- OAuth2 PKCE
CREATE TABLE oauth2_pkce (
    signature       TEXT PRIMARY KEY,
    request_id      TEXT NOT NULL,
    client_id       TEXT NOT NULL REFERENCES oauth2_clients(id),
    session_data    BYTEA NOT NULL,
    requested_at    TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    active          BOOLEAN NOT NULL DEFAULT TRUE
);

-- OIDC Sessions
CREATE TABLE oauth2_oidc_sessions (
    signature       TEXT PRIMARY KEY,
    request_id      TEXT NOT NULL,
    client_id       TEXT NOT NULL REFERENCES oauth2_clients(id),
    session_data    BYTEA NOT NULL,
    requested_at    TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    active          BOOLEAN NOT NULL DEFAULT TRUE
);

-- Signing Keys
CREATE TABLE signing_keys (
    id              TEXT PRIMARY KEY,
    algorithm       TEXT NOT NULL,
    private_key     BYTEA NOT NULL,
    public_key      TEXT NOT NULL,
    use_type        TEXT NOT NULL DEFAULT 'sig' CHECK (use_type IN ('sig', 'enc')),
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ
);

-- Audit Events
CREATE TABLE audit_events (
    id              BIGSERIAL PRIMARY KEY,
    actor_id        TEXT NOT NULL DEFAULT '',
    actor_type      TEXT NOT NULL DEFAULT 'system' CHECK (actor_type IN ('user', 'agent', 'client', 'system')),
    action          TEXT NOT NULL,
    resource_type   TEXT NOT NULL DEFAULT '',
    resource_id     TEXT NOT NULL DEFAULT '',
    org_id          UUID,
    ip              INET,
    user_agent      TEXT NOT NULL DEFAULT '',
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_created ON audit_events(created_at);
CREATE INDEX idx_audit_actor ON audit_events(actor_id, actor_type);
CREATE INDEX idx_audit_resource ON audit_events(resource_type, resource_id);
