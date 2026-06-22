-- Anchor checkpoints for the audit chain. A hash chain only proves integrity
-- RELATIVE TO A PINNED HEAD: deleting the newest rows (tail truncation) or
-- recomputing every hash from a tampered row forward both leave a chain that
-- verifies internally. `legant audit verify` records the current head (event
-- count + head hash) here on each successful run, and the NEXT run compares
-- against the latest anchor to catch a shrunken count or a changed prefix.
--
-- For full tamper-evidence this table should be shipped to an append-only /
-- separate-privilege store (an attacker with write access to BOTH tables can
-- still forge both). It raises the bar; it is not a substitute for off-box
-- notarization.
CREATE TABLE audit_anchors (
    id          BIGSERIAL PRIMARY KEY,
    event_count BIGINT NOT NULL,
    head_hash   TEXT NOT NULL,
    head_seq    BIGINT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
