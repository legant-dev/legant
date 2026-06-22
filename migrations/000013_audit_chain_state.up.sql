-- Watermark for the audit hash chain's genesis. Audit-event retention
-- (legant maintenance prune --audit-retention) deletes the OLDEST rows; the new
-- lowest-seq row's prev_hash then points to a now-deleted predecessor, which
-- would otherwise make `legant audit verify` report a (spurious) link break.
-- Recording that expected prev_hash here lets verify keep validating the
-- remaining chain while STILL detecting tampering that removes rows beyond what
-- was legitimately pruned (the new genesis's prev_hash must equal the watermark).
CREATE TABLE audit_chain_state (
    id        BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    watermark TEXT NOT NULL DEFAULT ''
);
INSERT INTO audit_chain_state (id) VALUES (TRUE);
