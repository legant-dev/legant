package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/legant-dev/legant/internal/db"
	"github.com/legant-dev/legant/internal/testsupport"
)

func TestWithTxCommitAndRollback(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS withtx_probe (n int)`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DROP TABLE IF EXISTS withtx_probe`) })
	if _, err := pool.Exec(ctx, `TRUNCATE withtx_probe`); err != nil {
		t.Fatal(err)
	}

	// Rollback: the inserted row must not persist when fn returns an error.
	err := db.WithTx(ctx, pool, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `INSERT INTO withtx_probe (n) VALUES (1)`); e != nil {
			return e
		}
		return errors.New("boom")
	})
	if err == nil {
		t.Fatal("expected the error to propagate")
	}
	if n := count(t, pool); n != 0 {
		t.Fatalf("rollback failed: want 0 rows, got %d", n)
	}

	// Commit: the inserted row must persist on success.
	err = db.WithTx(ctx, pool, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO withtx_probe (n) VALUES (2)`)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := count(t, pool); n != 1 {
		t.Fatalf("commit failed: want 1 row, got %d", n)
	}
}

func count(t *testing.T, pool interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM withtx_probe`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
