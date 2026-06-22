package grants

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/legant-dev/legant/sdk"
)

func famt(f float64) *float64 { return &f }

// a valid two-grant file (root + attenuated child) used across tests.
func sampleFile() *File {
	return &File{
		Version:  1,
		Audience: "https://api.test",
		Grants: []GrantSpec{
			{
				Name: "analytics", Principal: "user:alice", Agent: "agent:copilot",
				Scopes: []string{"warehouse:query"}, Audience: "warehouse://test",
				Constraints: &ConstraintSpec{Resources: []string{"sales", "finance"}},
			},
			{
				Name: "payments", Principal: "user:treasury", Agent: "agent:pay",
				Scopes:      []string{"transfer:prepare"},
				Constraints: &ConstraintSpec{MaxAmount: famt(5000)},
				Delegate: []ChildSpec{{
					Agent: "agent:reconciler", Scopes: []string{"transfer:prepare"},
					Constraints: &ConstraintSpec{MaxAmount: famt(500)},
				}},
			},
		},
	}
}

func TestLintClean(t *testing.T) {
	if issues := sampleFile().Lint(); HasErrors(issues) {
		t.Fatalf("expected clean lint, got %v", issues)
	}
}

func TestLintCatchesErrors(t *testing.T) {
	cases := map[string]*File{
		"empty scopes": {Audience: "a://b", Grants: []GrantSpec{{Principal: "user:x", Agent: "agent:y"}}},
		"self delegation": {Audience: "a://b", Grants: []GrantSpec{
			{Principal: "user:x", Agent: "user:x", Scopes: []string{"s"}}}},
		"missing audience": {Grants: []GrantSpec{
			{Principal: "user:x", Agent: "agent:y", Scopes: []string{"s"}}}},
		"escalating child": {Audience: "a://b", Grants: []GrantSpec{{
			Principal: "user:x", Agent: "agent:p", Scopes: []string{"doc:read"},
			Delegate: []ChildSpec{{Agent: "agent:c", Scopes: []string{"doc:read", "doc:delete"}}},
		}}},
		"bad window": {Audience: "a://b", Grants: []GrantSpec{{
			Principal: "user:x", Agent: "agent:y", Scopes: []string{"s"},
			Constraints: &ConstraintSpec{TimeWindow: &TimeWindowSpec{Start: "17:00", End: "09:00"}},
		}}},
		"negative amount": {Audience: "a://b", Grants: []GrantSpec{{
			Principal: "user:x", Agent: "agent:y", Scopes: []string{"s"},
			Constraints: &ConstraintSpec{MaxAmount: famt(-1)},
		}}},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			if !HasErrors(f.Lint()) {
				t.Fatalf("expected lint errors for %q, got none", name)
			}
		})
	}
}

func TestApplyIdempotent(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	f := sampleFile()
	s, err := EnsureSetup(dir, "", now)
	if err != nil {
		t.Fatal(err)
	}
	r1, err := f.Apply(s, false, now)
	if err != nil {
		t.Fatal(err)
	}
	// 2 roots + 1 child = 3 tokens, all created.
	if r1.Minted != 3 || len(r1.Changes) != 3 {
		t.Fatalf("first apply: minted=%d changes=%d want 3/3", r1.Minted, len(r1.Changes))
	}
	for _, c := range r1.Changes {
		if c.Action != "create" {
			t.Fatalf("first apply: %s action=%s want create", c.Name, c.Action)
		}
	}
	// Re-apply: nothing changes, nothing re-minted.
	r2, err := f.Apply(s, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Minted != 0 {
		t.Fatalf("second apply re-minted %d tokens; want 0 (idempotent)", r2.Minted)
	}
	for _, c := range r2.Changes {
		if c.Action != "unchanged" {
			t.Fatalf("second apply: %s action=%s want unchanged", c.Name, c.Action)
		}
	}
}

func TestApplyDetectsChange(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	f := sampleFile()
	s, _ := EnsureSetup(dir, "", now)
	if _, err := f.Apply(s, false, now); err != nil {
		t.Fatal(err)
	}
	// Tighten the payments cap: the same-named grant must show "update".
	f.Grants[1].Constraints.MaxAmount = famt(1000)
	r, err := f.Apply(s, false, now)
	if err != nil {
		t.Fatal(err)
	}
	var sawUpdate bool
	for _, c := range r.Changes {
		if c.Name == "payments" && c.Agent == "agent:pay" {
			if c.Action != "update" {
				t.Fatalf("changed grant action=%s want update", c.Action)
			}
			sawUpdate = true
		}
	}
	if !sawUpdate {
		t.Fatal("did not observe the updated grant")
	}
}

func TestApplyOrphanAndPrune(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	f := sampleFile()
	s, _ := EnsureSetup(dir, "", now)
	if _, err := f.Apply(s, false, now); err != nil {
		t.Fatal(err)
	}
	// Drop the payments grant; its two token files become orphans.
	f.Grants = f.Grants[:1]
	r, err := f.Apply(s, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Orphans) != 2 {
		t.Fatalf("orphans=%v want 2", r.Orphans)
	}
	if _, err := s.Prune(r.Orphans, now); err != nil {
		t.Fatal(err)
	}
	for _, o := range r.Orphans {
		if _, err := os.Stat(filepath.Join(dir, o)); !os.IsNotExist(err) {
			t.Fatalf("orphan %s not removed", o)
		}
	}
}

func TestWhoCan(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	f := sampleFile()
	s, _ := EnsureSetup(dir, "", now)

	// In-resource query → the analytics grant matches.
	m, err := f.WhoCan(s, sdk.Action{Scope: "warehouse:query", Resource: "finance"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 1 || m[0].Name != "analytics" {
		t.Fatalf("finance query matches=%v want [analytics]", m)
	}

	// Out-of-resource query → nothing.
	if m, _ := f.WhoCan(s, sdk.Action{Scope: "warehouse:query", Resource: "hr"}, now); len(m) != 0 {
		t.Fatalf("hr query matched %v want none", m)
	}

	// Under the cap → both payments nodes (root $5000, child $500) match.
	if m, _ := f.WhoCan(s, sdk.Action{Scope: "transfer:prepare", Amount: 300}, now); len(m) != 2 {
		t.Fatalf("under-cap matches=%d want 2", len(m))
	}
	// Over the child cap but under the root → only the root.
	m2, _ := f.WhoCan(s, sdk.Action{Scope: "transfer:prepare", Amount: 1000}, now)
	if len(m2) != 1 {
		t.Fatalf("between-caps matches=%d want 1 (root only)", len(m2))
	}
	// Over both caps → none.
	if m, _ := f.WhoCan(s, sdk.Action{Scope: "transfer:prepare", Amount: 9000}, now); len(m) != 0 {
		t.Fatalf("over-cap matched %v want none", m)
	}
}

func TestWhoCanTimeBoxed(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	f := &File{Audience: "a://b", Grants: []GrantSpec{{
		Name: "afterhours", Principal: "user:x", Agent: "agent:y", Scopes: []string{"s"},
		Constraints: &ConstraintSpec{
			Resources: []string{"r"},
			// A window that is never open (start==end==00:00 only matches midnight minute).
			TimeWindow: &TimeWindowSpec{Start: "00:00", End: "00:00", Weekdays: []int{}},
		},
	}}}
	s, _ := EnsureSetup(dir, "", now)
	m, err := f.WhoCan(s, sdk.Action{Scope: "s", Resource: "r"}, now)
	if err != nil {
		t.Fatal(err)
	}
	// Structurally capable but (almost certainly) outside the 1-minute window now.
	if len(m) != 1 {
		t.Fatalf("matches=%d want 1", len(m))
	}
	if !m[0].TimeBoxed {
		// If the test happens to run during 00:00 UTC minute it'd be permitted outright.
		if now.UTC().Hour() != 0 || now.UTC().Minute() != 0 {
			t.Fatalf("expected TimeBoxed match, got %+v", m[0])
		}
	}
}

func TestParseRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "g.yaml")
	os.WriteFile(p, []byte("version: 1\ngrants:\n  - principal: user:x\n    agent: agent:y\n    scopes: [s]\n    maxamount: 5\n"), 0o600)
	if _, err := Parse(p); err == nil {
		t.Fatal("expected parse error on unknown field 'maxamount'")
	}
}

func TestParseRoundTripStarter(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "starter.yaml")
	if err := os.WriteFile(p, []byte(StarterYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := Parse(p)
	if err != nil {
		t.Fatalf("starter template does not parse: %v", err)
	}
	if issues := f.Lint(); HasErrors(issues) {
		t.Fatalf("starter template does not lint clean: %v", issues)
	}
}
