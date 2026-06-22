package audit

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AnchorSigner provides the active signing key — the SAME key published in the
// issuer's JWKS — so a signed anchor shares the existing trust root (the keystore
// satisfies this, as it does for the revocation feed).
type AnchorSigner interface {
	ActiveKID() string
	ActiveSigner() *rsa.PrivateKey
}

// AnchorRecord is a self-describing, signed checkpoint of the audit chain. Ship it
// to an append-only / off-box store; `legant audit anchor --check` validates the
// live database against it. The signature covers the canonical tuple below, so a
// shipped copy cannot be forged without the signing key.
type AnchorRecord struct {
	Count     int64  `json:"count"`      // events at the time of anchoring
	HeadHash  string `json:"head_hash"`  // hash of the head event
	HeadSeq   int64  `json:"head_seq"`   // seq of the head event
	CreatedAt int64  `json:"created_at"` // unix seconds when anchored
	KID       string `json:"kid"`        // signing key id (look up in the JWKS)
	Signature string `json:"signature"`  // base64 RS256 over canonicalAnchor(...)
}

// canonicalAnchor is the exact byte string that is signed and verified. Any change
// to count/head_hash/head_seq/created_at changes it, so the signature pins all of
// them.
func canonicalAnchor(count int64, headHash string, headSeq, createdAt int64) []byte {
	return []byte(fmt.Sprintf("legant-audit-anchor:v1\ncount=%d\nhead_hash=%s\nhead_seq=%d\ncreated_at=%d",
		count, headHash, headSeq, createdAt))
}

// AnchorSigned verifies the chain, signs a checkpoint with the active key, stores
// it, and returns the signed record. Refuses to anchor a broken or empty chain.
func AnchorSigned(ctx context.Context, pool *pgxpool.Pool, signer AnchorSigner) (AnchorRecord, error) {
	res, err := Verify(ctx, pool)
	if err != nil {
		return AnchorRecord{}, err
	}
	if !res.OK {
		return AnchorRecord{}, fmt.Errorf("refusing to anchor a broken chain (%s break at id=%d)", res.BreakKind, res.BreakID)
	}
	if res.Events == 0 {
		return AnchorRecord{}, fmt.Errorf("refusing to anchor an empty chain")
	}
	rec := AnchorRecord{
		Count: res.Events, HeadHash: res.HeadHash, HeadSeq: res.HeadSeq,
		CreatedAt: time.Now().UTC().Unix(), KID: signer.ActiveKID(),
	}
	digest := sha256.Sum256(canonicalAnchor(rec.Count, rec.HeadHash, rec.HeadSeq, rec.CreatedAt))
	sig, err := rsa.SignPKCS1v15(rand.Reader, signer.ActiveSigner(), crypto.SHA256, digest[:])
	if err != nil {
		return AnchorRecord{}, fmt.Errorf("sign anchor: %w", err)
	}
	rec.Signature = base64.StdEncoding.EncodeToString(sig)

	if _, err := pool.Exec(ctx,
		`INSERT INTO audit_anchors (event_count, head_hash, head_seq, created_at, kid, signature)
		 VALUES ($1, $2, $3, to_timestamp($4), $5, $6)`,
		rec.Count, rec.HeadHash, rec.HeadSeq, rec.CreatedAt, rec.KID, rec.Signature); err != nil {
		return AnchorRecord{}, fmt.Errorf("store anchor: %w", err)
	}
	return rec, nil
}

// VerifyAnchorSignature checks a record's signature against the public key named
// by its kid. Fails closed on an unknown kid.
func VerifyAnchorSignature(rec AnchorRecord, keys map[string]*rsa.PublicKey) error {
	pub, ok := keys[rec.KID]
	if !ok {
		return fmt.Errorf("anchor signed by unknown key %q", rec.KID)
	}
	sig, err := base64.StdEncoding.DecodeString(rec.Signature)
	if err != nil {
		return fmt.Errorf("anchor signature not base64: %w", err)
	}
	digest := sha256.Sum256(canonicalAnchor(rec.Count, rec.HeadHash, rec.HeadSeq, rec.CreatedAt))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return fmt.Errorf("anchor signature invalid: %w", err)
	}
	return nil
}

// CheckAgainstAnchor is the off-box tamper-evidence check: it verifies the live
// chain internally, validates the external anchor's signature, and then proves
// the live chain still matches that trusted anchor — so it detects truncation or
// a rewritten prefix even if the database's own audit_anchors table was forged.
func CheckAgainstAnchor(ctx context.Context, pool *pgxpool.Pool, ext AnchorRecord, keys map[string]*rsa.PublicKey) (VerifyResult, error) {
	if err := VerifyAnchorSignature(ext, keys); err != nil {
		return VerifyResult{}, err
	}
	res, err := Verify(ctx, pool)
	if err != nil {
		return res, err
	}
	if !res.OK {
		return res, nil // internal break already found
	}
	if res.Events < ext.Count {
		res.OK, res.BreakKind = false, "truncation"
		return res, nil
	}
	var hashAtAnchor string
	if err := pool.QueryRow(ctx,
		`SELECT hash FROM audit_events ORDER BY seq LIMIT 1 OFFSET $1`, ext.Count-1).Scan(&hashAtAnchor); err != nil {
		if err == pgx.ErrNoRows {
			res.OK, res.BreakKind = false, "truncation"
			return res, nil
		}
		return res, err
	}
	if hashAtAnchor != ext.HeadHash {
		res.OK, res.BreakKind = false, "prefix"
	}
	return res, nil
}
