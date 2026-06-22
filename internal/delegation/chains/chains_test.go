package chains_test

import (
	"context"
	"testing"
	"time"

	"github.com/legant-dev/legant/internal/delegation"
	"github.com/legant-dev/legant/internal/delegation/chains"
	"github.com/legant-dev/legant/internal/testsupport"
)

func TestMultiHopDelegation(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()
	svc := chains.NewService(pool, nil)

	var userID, agentA, agentB string
	pool.QueryRow(ctx, `INSERT INTO users (email,status) VALUES ('u@x.com','active') RETURNING id::text`).Scan(&userID)
	pool.QueryRow(ctx, `INSERT INTO agents (name,type) VALUES ('A','ai_agent') RETURNING id::text`).Scan(&agentA)
	pool.QueryRow(ctx, `INSERT INTO agents (name,type) VALUES ('B','ai_agent') RETURNING id::text`).Scan(&agentB)

	// user -> agentA (read, write)
	_, parentDel, err := svc.GrantConsent(ctx, chains.ConsentRequest{
		UserID: userID, AgentID: agentA, Scopes: []string{"read", "write"},
		Constraints: delegation.Constraints{Resources: []string{"https://api.example"}},
		Resource:    "https://api.example", TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	// agentA re-delegates an attenuated slice (read only) to agentB.
	childDel, err := svc.Redelegate(ctx, parentDel, agentA, agentB, []string{"read"}, delegation.Constraints{}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Resolving the chain at the leaf (agentB), rooted at the user.
	g, leafID, err := svc.ResolveGrantChain(ctx, agentB, userID)
	if err != nil {
		t.Fatal(err)
	}
	if leafID != childDel {
		t.Fatalf("leaf id = %q, want %q", leafID, childDel)
	}
	if g.RootDelegator() != "user:"+userID {
		t.Fatalf("chain must be rooted at the user, got %q", g.RootDelegator())
	}
	chain := g.ActorChainRootToLeaf()
	if len(chain) != 2 || chain[0] != "agent:"+agentA || chain[1] != "agent:"+agentB {
		t.Fatalf("act chain = %v, want [agent:A agent:B]", chain)
	}
	// Scope attenuated through the chain: agentB only holds read.
	if eff := g.EffectiveScopes([]string{"read", "write"}); len(eff) != 1 || eff[0] != "read" {
		t.Fatalf("effective scopes = %v, write must be dropped", eff)
	}
	// The resource constraint is inherited (tightened) from the parent, in its
	// RFC 8707 canonical form (trailing slash added at storage time).
	if !hasResource(g.Constraints.Resources, "https://api.example/") {
		t.Fatalf("resource constraint must be inherited, got %v", g.Constraints.Resources)
	}

	// Re-delegating a scope the parent lacks is rejected.
	if _, err := svc.Redelegate(ctx, childDel, agentB, agentA, []string{"admin"}, delegation.Constraints{}, time.Hour); err == nil {
		t.Fatal("scope escalation must be rejected")
	}
	// Re-delegating to an agent already in the chain is rejected (cycle).
	if _, err := svc.Redelegate(ctx, childDel, agentB, agentA, []string{"read"}, delegation.Constraints{}, time.Hour); err == nil {
		t.Fatal("a cycle must be rejected")
	}
	// Only the holder may re-delegate.
	if _, err := svc.Redelegate(ctx, parentDel, agentB, agentB, []string{"read"}, delegation.Constraints{}, time.Hour); err == nil {
		t.Fatal("a non-holder must not be able to re-delegate")
	}

	// Revoking a middle link breaks chain resolution.
	pool.Exec(ctx, `UPDATE delegation_chains SET active=false WHERE id=$1`, parentDel)
	if _, _, err := svc.ResolveGrantChain(ctx, agentB, userID); err == nil {
		t.Fatal("revoking a middle link must break chain resolution")
	}
}

func TestRedelegateRejectsBadDelegateeAndConstraints(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()
	svc := chains.NewService(pool, nil)

	var userID, agentA, suspended, crossOrg, org string
	pool.QueryRow(ctx, `INSERT INTO users (email,status) VALUES ('u@x.com','active') RETURNING id::text`).Scan(&userID)
	pool.QueryRow(ctx, `INSERT INTO agents (name,type) VALUES ('A','ai_agent') RETURNING id::text`).Scan(&agentA)
	pool.QueryRow(ctx, `INSERT INTO agents (name,type,status) VALUES ('S','ai_agent','suspended') RETURNING id::text`).Scan(&suspended)
	pool.QueryRow(ctx, `INSERT INTO orgs (slug,name) VALUES ('o','o') RETURNING id::text`).Scan(&org)
	pool.QueryRow(ctx, `INSERT INTO agents (name,type,org_id) VALUES ('X','ai_agent',$1) RETURNING id::text`, org).Scan(&crossOrg)

	_, root, err := svc.GrantConsent(ctx, chains.ConsentRequest{
		UserID: userID, AgentID: agentA, Scopes: []string{"read"}, TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := svc.Redelegate(ctx, root, agentA, suspended, []string{"read"}, delegation.Constraints{}, time.Hour); err == nil {
		t.Error("re-delegation to a suspended agent must be rejected")
	}
	if _, err := svc.Redelegate(ctx, root, agentA, crossOrg, []string{"read"}, delegation.Constraints{}, time.Hour); err == nil {
		t.Error("re-delegation to a cross-org agent must be rejected")
	}
	// Negative rate is rejected at consent time.
	if _, _, err := svc.GrantConsent(ctx, chains.ConsentRequest{
		UserID: userID, AgentID: agentA, Scopes: []string{"read"},
		Constraints: delegation.Constraints{Rate: &delegation.RateLimit{MaxPerHour: -1}}, TTL: time.Hour,
	}); err == nil {
		t.Error("a negative rate must be rejected")
	}
}

func hasResource(rs []string, v string) bool {
	for _, r := range rs {
		if r == v {
			return true
		}
	}
	return false
}

func TestListAndRevokeDelegationTree(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()
	svc := chains.NewService(pool, nil)

	var userID, agentA, agentB string
	pool.QueryRow(ctx, `INSERT INTO users (email,status) VALUES ('u@x.com','active') RETURNING id::text`).Scan(&userID)
	pool.QueryRow(ctx, `INSERT INTO agents (name,type) VALUES ('Assistant','ai_agent') RETURNING id::text`).Scan(&agentA)
	pool.QueryRow(ctx, `INSERT INTO agents (name,type) VALUES ('OCR','ai_agent') RETURNING id::text`).Scan(&agentB)

	max := 500.0
	_, rootDel, err := svc.GrantConsent(ctx, chains.ConsentRequest{
		UserID: userID, AgentID: agentA, Scopes: []string{"read", "write"},
		Constraints: delegation.Constraints{Resources: []string{"https://api.example"}, MaxAmount: &max},
		Resource:    "https://api.example", TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	childDel, err := svc.Redelegate(ctx, rootDel, agentA, agentB, []string{"read"}, delegation.Constraints{}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// The user's list shows only their ROOT grant, not the agent's re-delegation.
	list, err := svc.ListUserDelegations(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != rootDel || list[0].AgentName != "Assistant" || !list[0].Active {
		t.Fatalf("list should contain only the active root grant, got %+v", list)
	}

	// Seed a live token against both the root and the child delegation.
	for _, del := range []string{rootDel, childDel} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO exchanged_tokens (jti, delegation_id, subject, audience, scopes, expires_at)
			 VALUES ($1,$2,'user','api','{read}', now()+interval '1 hour')`, "jti-"+del, del); err != nil {
			t.Fatal(err)
		}
	}

	// A non-owner cannot revoke.
	var other string
	pool.QueryRow(ctx, `INSERT INTO users (email,status) VALUES ('o@x.com','active') RETURNING id::text`).Scan(&other)
	if _, _, err := svc.RevokeDelegationTree(ctx, rootDel, other); err == nil {
		t.Fatal("a non-owner must not be able to revoke")
	}

	// The owner revokes the root → root + child deactivated, both tokens revoked.
	dRev, tRev, err := svc.RevokeDelegationTree(ctx, rootDel, userID)
	if err != nil {
		t.Fatal(err)
	}
	if dRev != 2 {
		t.Errorf("delegations revoked = %d, want 2 (root + child)", dRev)
	}
	if tRev != 2 {
		t.Errorf("tokens revoked = %d, want 2", tRev)
	}
	// The whole chain is dead.
	if _, _, err := svc.ResolveGrantChain(ctx, agentB, userID); err == nil {
		t.Error("a revoked chain must not resolve")
	}
	var liveTokens int
	pool.QueryRow(ctx, `SELECT count(*) FROM exchanged_tokens WHERE revoked_at IS NULL`).Scan(&liveTokens)
	if liveTokens != 0 {
		t.Errorf("live tokens after revoke = %d, want 0", liveTokens)
	}
	// The root now shows as revoked in the list.
	list, _ = svc.ListUserDelegations(ctx, userID)
	if len(list) != 1 || list[0].Active {
		t.Errorf("root should appear revoked in the list, got %+v", list)
	}
}
