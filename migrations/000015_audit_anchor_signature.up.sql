-- Sign audit anchors so an exported copy is self-verifying off-box. The signature
-- is over the canonical (count, head_hash, head_seq, created_at) tuple, made with
-- the active signing key (same key published in the JWKS). An attacker with write
-- access to both audit_events and audit_anchors still cannot forge a NEW valid
-- anchor without the signing key, and a copy shipped to an append-only store is
-- the trusted reference `legant audit anchor --check` validates the live DB
-- against.
ALTER TABLE audit_anchors ADD COLUMN signature TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_anchors ADD COLUMN kid TEXT NOT NULL DEFAULT '';
