-- Monotonic version for the signed revocation feed (/.well-known/revoked).
-- The feed JWT carries nextval, and SDKs reject a feed whose version regresses
-- (anti-rollback / replay), so a stale feed can never un-revoke a token.
CREATE SEQUENCE IF NOT EXISTS revocation_feed_version;
