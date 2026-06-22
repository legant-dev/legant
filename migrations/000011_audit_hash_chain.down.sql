DROP TRIGGER IF EXISTS audit_events_chain_trg ON audit_events;
DROP FUNCTION IF EXISTS audit_events_chain();
DROP FUNCTION IF EXISTS audit_row_hash(text, text, text, text, text, text, text, text[], uuid, text, uuid, inet, text, jsonb, timestamptz);
DROP INDEX IF EXISTS idx_audit_seq;
ALTER TABLE audit_events DROP COLUMN IF EXISTS seq;
DROP SEQUENCE IF EXISTS audit_events_seq;
ALTER TABLE audit_events DROP COLUMN IF EXISTS hash;
ALTER TABLE audit_events DROP COLUMN IF EXISTS prev_hash;
