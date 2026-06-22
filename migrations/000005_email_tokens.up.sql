CREATE TABLE email_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type        TEXT NOT NULL CHECK (type IN ('verification', 'password_reset', 'magic_link')),
    token_hash  TEXT NOT NULL,
    email       TEXT NOT NULL,
    used        BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_email_tokens_hash ON email_tokens(token_hash);
CREATE INDEX idx_email_tokens_user ON email_tokens(user_id);
