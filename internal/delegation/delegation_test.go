package delegation

import (
	"testing"
	"time"

	legantcrypto "github.com/legant-dev/legant/internal/crypto"
)

func amount(v float64) *float64 { return &v }

func TestAttenuate(t *testing.T) {
	parent := []string{"expenses:read", "expenses:submit"}
	got := Attenuate(parent, []string{"expenses:submit", "expenses:approve"})
	if len(got) != 1 || got[0] != "expenses:submit" {
		t.Fatalf("attenuate dropped the wrong scopes: %v", got)
	}
}

func TestIsSubset(t *testing.T) {
	parent := []string{"a", "b", "c"}
	if !IsSubset([]string{"a", "c"}, parent) {
		t.Fatal("expected subset")
	}
	if IsSubset([]string{"a", "d"}, parent) {
		t.Fatal("expected non-subset")
	}
}

func TestConstraintsPermit(t *testing.T) {
	c := Constraints{MaxAmount: amount(500), Categories: []string{"travel", "meals"}}

	if err := c.Permit(Action{Amount: 120, Category: "travel"}); err != nil {
		t.Fatalf("in-bounds action denied: %v", err)
	}
	if err := c.Permit(Action{Amount: 900, Category: "travel"}); err == nil {
		t.Fatal("over-limit amount should be denied")
	}
	if err := c.Permit(Action{Amount: 50, Category: "gadgets"}); err == nil {
		t.Fatal("disallowed category should be denied")
	}
	// A read with no amount/category must pass amount & category checks.
	if err := c.Permit(Action{}); err != nil {
		t.Fatalf("zero-value action denied: %v", err)
	}
}

func TestTightenTakesStricter(t *testing.T) {
	parent := Constraints{MaxAmount: amount(500), Categories: []string{"travel", "meals", "office"}}
	child := Constraints{MaxAmount: amount(200), Categories: []string{"travel", "office"}}
	got := Tighten(parent, child)

	if got.MaxAmount == nil || *got.MaxAmount != 200 {
		t.Fatalf("expected tighter max_amount 200, got %v", got.MaxAmount)
	}
	if len(got.Categories) != 2 || !contains(got.Categories, "travel") || !contains(got.Categories, "office") {
		t.Fatalf("expected category intersection, got %v", got.Categories)
	}
}

func TestDelegateRejectsScopeEscalation(t *testing.T) {
	now := time.Now()
	root := NewRootGrant("user:alice", "agent:assistant",
		[]string{"expenses:read", "expenses:submit"}, Constraints{}, time.Hour, now)

	if _, err := root.Delegate("agent:ocr", []string{"expenses:approve"}, Constraints{}, time.Hour, now, DefaultMaxDepth); err == nil {
		t.Fatal("re-delegating a scope the parent lacks must fail")
	}
	if _, err := root.Delegate("agent:ocr", []string{"expenses:read"}, Constraints{}, time.Hour, now, DefaultMaxDepth); err != nil {
		t.Fatalf("attenuated re-delegation should succeed: %v", err)
	}
}

func TestDelegateRejectsCycle(t *testing.T) {
	now := time.Now()
	root := NewRootGrant("user:alice", "agent:assistant", []string{"x"}, Constraints{}, time.Hour, now)
	child, err := root.Delegate("agent:ocr", []string{"x"}, Constraints{}, time.Hour, now, DefaultMaxDepth)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := child.Delegate("agent:assistant", []string{"x"}, Constraints{}, time.Hour, now, DefaultMaxDepth); err == nil {
		t.Fatal("re-introducing a principal already in the chain must fail")
	}
}

func TestDelegateRejectsDepth(t *testing.T) {
	now := time.Now()
	g := NewRootGrant("user:alice", "agent:a0", []string{"x"}, Constraints{}, time.Hour, now)
	// maxDepth=2 allows root (depth 0) + one re-delegation (depth 1); the next must fail.
	child, err := g.Delegate("agent:a1", []string{"x"}, Constraints{}, time.Hour, now, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := child.Delegate("agent:a2", []string{"x"}, Constraints{}, time.Hour, now, 2); err == nil {
		t.Fatal("exceeding max depth must fail")
	}
}

func TestChildExpiryBoundedByParent(t *testing.T) {
	now := time.Now()
	root := NewRootGrant("user:alice", "agent:assistant", []string{"x"}, Constraints{}, time.Minute, now)
	child, err := root.Delegate("agent:ocr", []string{"x"}, Constraints{}, time.Hour, now, DefaultMaxDepth)
	if err != nil {
		t.Fatal(err)
	}
	if child.ExpiresAt.After(root.ExpiresAt) {
		t.Fatal("child grant must not outlive its parent")
	}
}

// End-to-end: issue a composite token for a two-hop chain and verify the
// resource server can validate it, read the provenance, and authorize actions.
func TestIssueAndVerifyChain(t *testing.T) {
	now := time.Now()
	key, err := legantcrypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	signer := NewSigner("https://legant.test", "test-key", key)
	verifier := NewSingleKeyVerifier("https://legant.test", "test-key", &key.PublicKey)

	root := NewRootGrant("user:alice", "agent:assistant",
		[]string{"expenses:read", "expenses:submit"},
		Constraints{MaxAmount: amount(500), Categories: []string{"travel", "meals"}, Resources: []string{"finance-api"}},
		time.Hour, now)
	child, err := root.Delegate("agent:ocr", []string{"expenses:read"}, Constraints{}, time.Hour, now, DefaultMaxDepth)
	if err != nil {
		t.Fatal(err)
	}

	tokenStr, err := signer.IssueForGrant(child, []string{"expenses:read"}, "finance-api", now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	claims, err := verifier.Verify(tokenStr, "finance-api")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if claims.Subject != "user:alice" {
		t.Fatalf("subject should be the resource owner, got %q", claims.Subject)
	}
	if got, want := claims.Provenance(), "user:alice -> agent:assistant -> agent:ocr"; got != want {
		t.Fatalf("provenance = %q, want %q", got, want)
	}
	if err := claims.Authorize(Action{Scope: "expenses:read"}); err != nil {
		t.Fatalf("read should be authorized: %v", err)
	}
	if err := claims.Authorize(Action{Scope: "expenses:submit"}); err == nil {
		t.Fatal("submit was never delegated to the OCR sub-agent; must be denied")
	}
}

func TestVerifyRejectsWrongAudience(t *testing.T) {
	now := time.Now()
	key, _ := legantcrypto.GenerateRSAKey(2048)
	signer := NewSigner("https://legant.test", "k", key)
	verifier := NewSingleKeyVerifier("https://legant.test", "k", &key.PublicKey)

	g := NewRootGrant("user:alice", "agent:assistant", []string{"expenses:read"}, Constraints{}, time.Hour, now)
	tok, err := signer.IssueForGrant(g, []string{"expenses:read"}, "finance-api", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(tok, "calendar-api"); err == nil {
		t.Fatal("token bound to finance-api must not validate for calendar-api")
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	past := time.Now().Add(-2 * time.Hour)
	key, _ := legantcrypto.GenerateRSAKey(2048)
	signer := NewSigner("https://legant.test", "k", key)
	verifier := NewSingleKeyVerifier("https://legant.test", "k", &key.PublicKey)

	g := NewRootGrant("user:alice", "agent:assistant", []string{"x"}, Constraints{}, time.Minute, past)
	tok, err := signer.IssueForGrant(g, []string{"x"}, "finance-api", past)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(tok, "finance-api"); err == nil {
		t.Fatal("expired token must be rejected")
	}
}

func TestConstraintBlocksAudience(t *testing.T) {
	now := time.Now()
	key, _ := legantcrypto.GenerateRSAKey(2048)
	signer := NewSigner("https://legant.test", "k", key)

	g := NewRootGrant("user:alice", "agent:assistant", []string{"x"},
		Constraints{Resources: []string{"finance-api"}}, time.Hour, now)
	if _, err := signer.IssueForGrant(g, []string{"x"}, "calendar-api", now); err == nil {
		t.Fatal("issuing for an audience excluded by constraints must fail")
	}
}

// A token signed under a kid the verifier does not hold (e.g. a retired or
// attacker-chosen key) must fail closed.
func TestVerifyRejectsUnknownKID(t *testing.T) {
	now := time.Now()
	key, _ := legantcrypto.GenerateRSAKey(2048)
	signer := NewSigner("https://legant.test", "rotated-out-kid", key)
	// Verifier only trusts a different kid.
	verifier := NewSingleKeyVerifier("https://legant.test", "current-kid", &key.PublicKey)

	g := NewRootGrant("user:alice", "agent:assistant", []string{"x"}, Constraints{}, time.Hour, now)
	tok, err := signer.IssueForGrant(g, []string{"x"}, "finance-api", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(tok, "finance-api"); err == nil {
		t.Fatal("token signed under an untrusted kid must be rejected")
	}
}
