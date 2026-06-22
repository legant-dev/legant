-- Tamper-evident audit: hash-chain every audit_events row to its predecessor.
-- An in-place edit, a mid-chain deletion, or a reorder breaks the chain and is
-- detected by `legant audit verify`. Two cases are NOT detectable from the chain
-- alone and require an external anchor (see the audit_anchors table in 000012):
-- deleting the NEWEST rows (tail truncation leaves a valid chain) and an attacker
-- with table-write access recomputing every hash from a tampered row forward.
-- The hash is computed in the database by a single shared function used by BOTH
-- the insert trigger and the verifier, so the two can never disagree on it.

ALTER TABLE audit_events ADD COLUMN prev_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN hash TEXT NOT NULL DEFAULT '';

-- The chain is ordered by seq, a value assigned INSIDE the chaining advisory lock
-- (below) so the chain order matches commit order. The BIGSERIAL id is assigned
-- before the lock and can diverge from commit order under concurrency, so it
-- must NOT be used to order the chain.
CREATE SEQUENCE IF NOT EXISTS audit_events_seq;
ALTER TABLE audit_events ADD COLUMN seq BIGINT;
CREATE INDEX idx_audit_seq ON audit_events(seq);

-- audit_row_hash is the single source of truth for an event's hash: SHA-256 over
-- the predecessor's hash plus every immutable field, unit-separated. Uses the
-- built-in sha256() (PostgreSQL 11+), so no extension is required.
CREATE OR REPLACE FUNCTION audit_row_hash(
    p_prev text, p_actor_type text, p_actor_id text, p_action text,
    p_resource_type text, p_resource_id text, p_obo text, p_actor_chain text[],
    p_delegation_id uuid, p_grant_jti text, p_org_id uuid,
    p_ip inet, p_user_agent text, p_metadata jsonb, p_created_at timestamptz
) RETURNS text LANGUAGE sql IMMUTABLE AS $$
    SELECT encode(sha256(convert_to(
        coalesce(p_prev,'')            || E'\x1f' || coalesce(p_actor_type,'')   || E'\x1f' ||
        coalesce(p_actor_id,'')        || E'\x1f' || coalesce(p_action,'')       || E'\x1f' ||
        coalesce(p_resource_type,'')   || E'\x1f' || coalesce(p_resource_id,'')  || E'\x1f' ||
        coalesce(p_obo,'')             || E'\x1f' || coalesce(array_to_string(p_actor_chain, ','),'') || E'\x1f' ||
        coalesce(p_delegation_id::text,'') || E'\x1f' || coalesce(p_grant_jti,'') || E'\x1f' ||
        coalesce(p_org_id::text,'')    || E'\x1f' || coalesce(p_ip::text,'')      || E'\x1f' ||
        coalesce(p_user_agent,'')      || E'\x1f' || coalesce(p_metadata::text,'') || E'\x1f' ||
        extract(epoch from p_created_at)::text
    , 'UTF8')), 'hex')
$$;

-- Seal any rows that predate this migration so the chain verifies from row one.
DO $$
DECLARE r RECORD; prev TEXT := '';
BEGIN
    FOR r IN SELECT * FROM audit_events ORDER BY id LOOP
        UPDATE audit_events SET
            seq = nextval('audit_events_seq'),
            prev_hash = prev,
            hash = audit_row_hash(prev, r.actor_type, r.actor_id, r.action,
                r.resource_type, r.resource_id, r.on_behalf_of_sub, r.actor_chain,
                r.delegation_id, r.grant_jti, r.org_id, r.ip, r.user_agent,
                r.metadata, r.created_at)
        WHERE id = r.id;
        SELECT hash INTO prev FROM audit_events WHERE id = r.id;
    END LOOP;
END $$;

-- BEFORE INSERT trigger chains every new row regardless of which code path wrote
-- it. An advisory xact lock serializes appends into a single linear chain (audit
-- is not the hot path, so the contention is acceptable for the integrity gained).
CREATE OR REPLACE FUNCTION audit_events_chain() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE prev TEXT;
BEGIN
    PERFORM pg_advisory_xact_lock(918273645);
    NEW.seq := nextval('audit_events_seq');
    SELECT hash INTO prev FROM audit_events ORDER BY seq DESC LIMIT 1;
    prev := COALESCE(prev, '');
    NEW.prev_hash := prev;
    NEW.hash := audit_row_hash(prev, NEW.actor_type, NEW.actor_id, NEW.action,
        NEW.resource_type, NEW.resource_id, NEW.on_behalf_of_sub, NEW.actor_chain,
        NEW.delegation_id, NEW.grant_jti, NEW.org_id, NEW.ip, NEW.user_agent,
        NEW.metadata, NEW.created_at);
    RETURN NEW;
END $$;

CREATE TRIGGER audit_events_chain_trg
    BEFORE INSERT ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_chain();
