package audit

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// VerifyResult is the outcome of an audit hash-chain verification.
type VerifyResult struct {
	Events    int64  // total events scanned
	OK        bool   // true if the whole chain verifies (and matches the last anchor)
	HeadHash  string // hash of the most recent event
	HeadSeq   int64  // seq of the most recent event
	BreakID   int64  // id of the first broken event (0 when OK or for a count regression)
	BreakKind string // "content" | "link" | "truncation" (rows removed vs the last anchor) | "prefix" (anchored prefix changed)
}

// Verify recomputes the audit hash chain in seq order and reports the first
// break. It reuses the in-database audit_row_hash function — the same one the
// insert trigger uses — so the verifier and the writer can never disagree.
//
// Per-row checks:
//   - content: stored hash == audit_row_hash(stored prev_hash, …fields). A
//     mismatch means a field was edited in place.
//   - link: stored prev_hash == the previous row's stored hash. A mismatch means
//     a row was inserted, deleted, or reordered mid-chain.
//
// Tail truncation and a full re-seal do not break the chain internally, so Verify
// additionally compares against the most recent anchor (see Anchor): a smaller
// event count is reported as "truncation", and a changed anchored prefix as
// "prefix".
func Verify(ctx context.Context, pool *pgxpool.Pool) (VerifyResult, error) {
	rows, err := pool.Query(ctx, `
		SELECT id, hash, prev_hash,
		    audit_row_hash(prev_hash, actor_type, actor_id, action, resource_type,
		        resource_id, on_behalf_of_sub, actor_chain, delegation_id, grant_jti,
		        org_id, ip, user_agent, metadata, created_at) AS computed,
		    lag(hash) OVER (ORDER BY seq) AS expected_prev,
		    seq
		FROM audit_events
		ORDER BY seq`)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("query audit chain: %w", err)
	}
	defer rows.Close()

	// The genesis row's prev_hash is "" on a fresh chain, or the watermark left by
	// audit retention when the original genesis rows were legitimately pruned.
	watermark := ""
	if err := pool.QueryRow(ctx, `SELECT watermark FROM audit_chain_state WHERE id`).Scan(&watermark); err != nil && err != pgx.ErrNoRows {
		return VerifyResult{}, fmt.Errorf("read audit watermark: %w", err)
	}

	res := VerifyResult{OK: true}
	for rows.Next() {
		var id, seq int64
		var hash, prevHash, computed string
		var expectedPrev *string
		if err := rows.Scan(&id, &hash, &prevHash, &computed, &expectedPrev, &seq); err != nil {
			return VerifyResult{}, fmt.Errorf("scan audit row: %w", err)
		}
		res.Events++
		res.HeadHash = hash
		res.HeadSeq = seq

		if !res.OK {
			continue
		}
		ep := watermark // first row: expected prev is the watermark
		if expectedPrev != nil {
			ep = *expectedPrev
		}
		switch {
		case prevHash != ep:
			res.OK, res.BreakID, res.BreakKind = false, id, "link"
		case hash != computed:
			res.OK, res.BreakID, res.BreakKind = false, id, "content"
		}
	}
	if err := rows.Err(); err != nil {
		return VerifyResult{}, fmt.Errorf("iterate audit chain: %w", err)
	}
	if !res.OK {
		return res, nil
	}

	// Compare against the last anchor to catch tail truncation / re-seal.
	var aCount int64
	var aHead string
	err = pool.QueryRow(ctx,
		`SELECT event_count, head_hash FROM audit_anchors ORDER BY id DESC LIMIT 1`).Scan(&aCount, &aHead)
	if err == pgx.ErrNoRows {
		return res, nil // nothing anchored yet
	}
	if err != nil {
		return VerifyResult{}, fmt.Errorf("read latest anchor: %w", err)
	}
	if res.Events < aCount {
		res.OK, res.BreakKind = false, "truncation" // rows removed since the last anchor
		return res, nil
	}
	// The row at the anchored position must still carry the anchored head hash.
	var hashAtAnchor string
	if err := pool.QueryRow(ctx,
		`SELECT hash FROM audit_events ORDER BY seq LIMIT 1 OFFSET $1`, aCount-1).Scan(&hashAtAnchor); err == nil {
		if hashAtAnchor != aHead {
			res.OK, res.BreakKind = false, "prefix" // the anchored prefix was rewritten
		}
	}
	return res, nil
}

// Anchor records the current chain head (event count + head hash) so a future
// Verify can detect tail truncation or a re-seal. Call it after a successful
// Verify. It is a no-op on an empty log.
func Anchor(ctx context.Context, pool *pgxpool.Pool) error {
	res, err := Verify(ctx, pool)
	if err != nil {
		return err
	}
	if !res.OK {
		return fmt.Errorf("refusing to anchor a broken chain (%s break at id=%d)", res.BreakKind, res.BreakID)
	}
	if res.Events == 0 {
		return nil
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO audit_anchors (event_count, head_hash, head_seq) VALUES ($1, $2, $3)`,
		res.Events, res.HeadHash, res.HeadSeq)
	return err
}
