package mcpgw

import (
	"context"
	"testing"

	"github.com/legant-dev/legant/internal/revocation"
	"github.com/legant-dev/legant/internal/testsupport"
)

func TestUpstreamRegistry(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()
	store := NewUpstreamStore(pool)

	if err := store.Upsert(ctx, &Upstream{Slug: "db1", InboundAudience: "https://gw/db1", URL: "http://u1", ResourceID: "https://rs1/", ToolScopes: map[string]string{"read": "x:read"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Upsert(ctx, &Upstream{Slug: "db2", InboundAudience: "https://gw/db2", URL: "http://u2", ResourceID: "https://rs2/"}); err != nil {
		t.Fatal(err)
	}
	list, err := store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("want 2 upstreams, got %d", len(list))
	}
	var db1 *Upstream
	for _, u := range list {
		if u.Slug == "db1" {
			db1 = u
		}
	}
	if db1 == nil || db1.ToolScopes["read"] != "x:read" {
		t.Errorf("tool_scopes did not round-trip through JSONB: %+v", db1)
	}

	// The gateway merges its static base with the DB registry.
	gw, err := NewGateway("https://issuer.test", nil, revocation.NewStore(pool, nil), pool, nil,
		[]*Upstream{{Slug: "static1", InboundAudience: "https://gw/static1", URL: "http://s1", ResourceID: "https://rss1/"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := gw.RefreshUpstreams(ctx, store); err != nil {
		t.Fatal(err)
	}
	if _, ok := gw.upstream("static1"); !ok {
		t.Error("static upstream must remain after a refresh")
	}
	if _, ok := gw.upstream("db1"); !ok {
		t.Error("a DB upstream must be picked up by RefreshUpstreams")
	}

	// A DB upstream that duplicates a static inbound_audience is skipped (isolation
	// is never weakened; static wins).
	if err := store.Upsert(ctx, &Upstream{Slug: "evil", InboundAudience: "https://gw/static1", URL: "http://e", ResourceID: "https://rse/"}); err != nil {
		t.Fatal(err)
	}
	if err := gw.RefreshUpstreams(ctx, store); err != nil {
		t.Fatal(err)
	}
	if _, ok := gw.upstream("evil"); ok {
		t.Error("a DB upstream duplicating a static inbound_audience must be skipped")
	}
	if u, ok := gw.upstream("static1"); !ok || u.URL != "http://s1" {
		t.Error("the static upstream must win the inbound_audience collision")
	}

	// Deletion drops the upstream on the next refresh.
	removed, err := store.Delete(ctx, "db2")
	if err != nil || !removed {
		t.Fatalf("delete db2: removed=%v err=%v", removed, err)
	}
	if err := gw.RefreshUpstreams(ctx, store); err != nil {
		t.Fatal(err)
	}
	if _, ok := gw.upstream("db2"); ok {
		t.Error("a deleted upstream must drop after the next refresh")
	}
}
