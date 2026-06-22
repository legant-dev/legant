// Package grants turns Legant's delegated authority into a declarative,
// version-controllable file. Instead of minting authority imperatively (CLI flags
// or a browser consent click), a team writes a `legant.grants.yaml` that says
// "principal P delegates to agent A the scopes S, capped by these constraints,"
// reviews it in a pull request, lints it in CI, and `apply`s it to materialize the
// signed tokens offline.
//
// It is deliberately NOT a policy language: the schema is a fixed, 1:1
// serialization of Legant's own constraint dimensions (max_amount, categories,
// tools, resources/RFC-8707 audiences, time_window). That fixedness is the whole
// point — it travels inside the token and verifies offline at any resource server,
// which an OPA/Kyverno-style content gate cannot do. Keep it from growing into a
// Turing-complete DSL.
package grants

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/legant-dev/legant/internal/ccguard"
	legantcrypto "github.com/legant-dev/legant/internal/crypto"
	"github.com/legant-dev/legant/internal/delegation"
	"github.com/legant-dev/legant/sdk"
	"gopkg.in/yaml.v3"
)

// File is a parsed legant.grants.yaml.
type File struct {
	Version  int         `yaml:"version"`
	Issuer   string      `yaml:"issuer,omitempty"`
	Audience string      `yaml:"audience,omitempty"` // default audience for grants that omit one
	Defaults Defaults    `yaml:"defaults,omitempty"`
	Grants   []GrantSpec `yaml:"grants"`
}

// Defaults are applied to any grant that omits the field.
type Defaults struct {
	TTL string `yaml:"ttl,omitempty"`
}

// GrantSpec is one root delegation: principal -> agent, with constraints and any
// further attenuated hand-offs in Delegate.
type GrantSpec struct {
	Name        string          `yaml:"name,omitempty"`
	Principal   string          `yaml:"principal"`
	Agent       string          `yaml:"agent"`
	Scopes      []string        `yaml:"scopes"`
	Audience    string          `yaml:"audience,omitempty"`
	TTL         string          `yaml:"ttl,omitempty"`
	Constraints *ConstraintSpec `yaml:"constraints,omitempty"`
	Delegate    []ChildSpec     `yaml:"delegate,omitempty"`
}

// ChildSpec is an attenuated sub-delegation of its parent grant.
type ChildSpec struct {
	Agent       string          `yaml:"agent"`
	Scopes      []string        `yaml:"scopes"`
	Constraints *ConstraintSpec `yaml:"constraints,omitempty"`
}

// ConstraintSpec maps 1:1 to delegation.Constraints (Legant's fixed dimensions).
type ConstraintSpec struct {
	MaxAmount  *float64        `yaml:"max_amount,omitempty"`
	Categories []string        `yaml:"categories,omitempty"`
	Tools      []string        `yaml:"tools,omitempty"`
	Resources  []string        `yaml:"resources,omitempty"`
	TimeWindow *TimeWindowSpec `yaml:"time_window,omitempty"`
	// Rate is intentionally NOT here: a rolling-hour cap needs shared state and is
	// enforced by Legant at mint time, never offline at a resource server. Declaring
	// it in a file that promises offline enforcement would be dishonest.
}

// TimeWindowSpec is a friendlier surface over delegation.TimeWindow: HH:MM strings
// instead of minute-of-day integers.
type TimeWindowSpec struct {
	Weekdays []int  `yaml:"weekdays,omitempty"` // 0=Sun..6=Sat; empty = any day
	Start    string `yaml:"start"`              // "09:00"
	End      string `yaml:"end"`                // "17:00"
	TZ       string `yaml:"tz,omitempty"`       // IANA name; empty = UTC
}

// Parse reads and unmarshals a grants file. It rejects unknown fields so a typo'd
// key fails loudly at lint time instead of being silently ignored.
func Parse(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &f, nil
}

// Issue is one lint finding. Error issues fail the lint (non-zero exit); Warn
// issues are advisory.
type Issue struct {
	Grant    string
	Severity string // "error" | "warn"
	Message  string
}

func (i Issue) String() string {
	mark := "warn "
	if i.Severity == "error" {
		mark = "ERROR"
	}
	where := ""
	if i.Grant != "" {
		where = " [" + i.Grant + "]"
	}
	return fmt.Sprintf("%s%s %s", mark, where, i.Message)
}

// Lint validates the file semantically WITHOUT side effects: it catches the errors
// that would otherwise silently 401/403 at runtime — an empty scope list, a child
// that widens past its parent, a time window that never opens, a missing audience,
// a duplicate grant. It returns every issue found (errors and warnings) so a CI
// gate can fail on errors.
func (f *File) Lint() []Issue {
	var issues []Issue
	add := func(g, sev, msg string) { issues = append(issues, Issue{Grant: g, Severity: sev, Message: msg}) }

	if f.Version != 0 && f.Version != 1 {
		add("", "warn", fmt.Sprintf("version %d is not understood (expected 1)", f.Version))
	}
	if len(f.Grants) == 0 {
		add("", "error", "no grants declared")
	}
	seen := map[string]bool{}
	for i, g := range f.Grants {
		name := g.label(i)
		if g.Principal == "" {
			add(name, "error", "principal is required (the delegating identity, e.g. user:alice)")
		}
		if g.Agent == "" {
			add(name, "error", "agent is required (the delegatee, e.g. agent:copilot)")
		}
		if g.Principal != "" && g.Principal == g.Agent {
			add(name, "error", "principal and agent must differ")
		}
		if len(g.Scopes) == 0 {
			add(name, "error", "scopes is required and must be non-empty")
		}
		if f.audienceFor(g) == "" {
			add(name, "error", "no audience: set grant.audience or a top-level audience (the resource server this token is for)")
		}
		if _, err := f.ttlFor(g); err != nil {
			add(name, "error", "ttl: "+err.Error())
		}
		key := g.Principal + "\x00" + g.Agent + "\x00" + f.audienceFor(g)
		if seen[key] {
			add(name, "warn", "duplicate grant (same principal, agent, and audience) — the later one wins")
		}
		seen[key] = true
		constraintErr := false
		if g.Constraints != nil {
			if _, err := g.Constraints.toConstraints(); err != nil {
				add(name, "error", "constraints: "+err.Error())
				constraintErr = true
			}
		}
		// Build the grant tree to catch attenuation escalation exactly as Apply would.
		// Skip it when the parent constraints are already invalid (buildTree would just
		// re-report the same constraint error).
		if !constraintErr {
			if _, _, err := f.buildTree(g, i, time.Now()); err != nil {
				add(name, "error", err.Error())
			}
		}
	}
	return issues
}

// HasErrors reports whether any issue is an error (for the lint exit code).
func HasErrors(issues []Issue) bool {
	for _, i := range issues {
		if i.Severity == "error" {
			return true
		}
	}
	return false
}

func (g GrantSpec) label(i int) string {
	if g.Name != "" {
		return g.Name
	}
	if g.Principal != "" && g.Agent != "" {
		return g.Principal + "->" + g.Agent
	}
	return fmt.Sprintf("grant#%d", i)
}

func (f *File) audienceFor(g GrantSpec) string {
	if g.Audience != "" {
		return g.Audience
	}
	return f.Audience
}

func (f *File) ttlFor(g GrantSpec) (time.Duration, error) {
	s := g.TTL
	if s == "" {
		s = f.Defaults.TTL
	}
	if s == "" {
		return time.Hour, nil // sensible default
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	if d <= 0 {
		return 0, fmt.Errorf("ttl must be positive")
	}
	return d, nil
}

func (f *File) issuer() string {
	if f.Issuer != "" {
		return f.Issuer
	}
	return ccguard.DefaultIssuer
}

// node is one materialized grant in a (possibly multi-hop) tree, with the filename
// its token is written to and the audience it is bound to.
type node struct {
	file     string
	grant    *delegation.Grant
	audience string
}

// buildTree constructs the root grant and any attenuated children, returning every
// node to be minted. Escalation (a child requesting a scope/constraint its parent
// lacks) surfaces here as an error — exactly as it will at apply time.
func (f *File) buildTree(g GrantSpec, idx int, now time.Time) (*delegation.Grant, []node, error) {
	ttl, err := f.ttlFor(g)
	if err != nil {
		return nil, nil, err
	}
	var cnst delegation.Constraints
	if g.Constraints != nil {
		cnst, err = g.Constraints.toConstraints()
		if err != nil {
			return nil, nil, err
		}
	}
	root := delegation.NewRootGrant(g.Principal, g.Agent, g.Scopes, cnst, ttl, now)
	aud := f.audienceFor(g)
	base := sanitize(g.label(idx))
	nodes := []node{{file: base + ".jwt", grant: root, audience: aud}}

	for ci, c := range g.Delegate {
		if c.Agent == "" {
			return nil, nil, fmt.Errorf("delegate #%d: agent is required", ci)
		}
		var ccnst delegation.Constraints
		if c.Constraints != nil {
			ccnst, err = c.Constraints.toConstraints()
			if err != nil {
				return nil, nil, fmt.Errorf("delegate %s: constraints: %w", c.Agent, err)
			}
		}
		child, derr := root.Delegate(c.Agent, c.Scopes, ccnst, ttl, now, delegation.DefaultMaxDepth)
		if derr != nil {
			// Delegate's error already names the delegatee ("delegate agent:child: …").
			return nil, nil, derr
		}
		nodes = append(nodes, node{file: base + "__" + sanitize(c.Agent) + ".jwt", grant: child, audience: aud})
	}
	return root, nodes, nil
}

// toConstraints converts the YAML shape into the engine's Constraints, validating
// the time window.
func (c *ConstraintSpec) toConstraints() (delegation.Constraints, error) {
	out := delegation.Constraints{
		Categories: c.Categories,
		Tools:      c.Tools,
		Resources:  c.Resources,
	}
	if c.MaxAmount != nil {
		if *c.MaxAmount < 0 {
			return out, fmt.Errorf("max_amount must be >= 0")
		}
		v := *c.MaxAmount
		out.MaxAmount = &v
	}
	if c.TimeWindow != nil {
		start, err := parseHHMM(c.TimeWindow.Start)
		if err != nil {
			return out, fmt.Errorf("time_window.start: %w", err)
		}
		end, err := parseHHMM(c.TimeWindow.End)
		if err != nil {
			return out, fmt.Errorf("time_window.end: %w", err)
		}
		tw := &delegation.TimeWindow{Weekdays: c.TimeWindow.Weekdays, StartMin: start, EndMin: end, TZ: c.TimeWindow.TZ}
		if err := tw.Validate(); err != nil {
			return out, fmt.Errorf("time_window: %w", err)
		}
		out.TimeWindow = tw
	}
	return out, nil
}

func parseHHMM(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("required (use HH:MM, e.g. 09:00)")
	}
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0, fmt.Errorf("%q is not HH:MM", s)
	}
	return t.Hour()*60 + t.Minute(), nil
}

// Setup is the offline trust material apply/mint operate on: a local signing key,
// its JWKS, and the signed revocation feed, all under one directory.
type Setup struct {
	Dir      string
	Issuer   string
	Signer   *delegation.Signer
	Keys     map[string]*rsa.PublicKey
	FeedPath string
	created  bool
}

// EnsureSetup loads the local key/JWKS/feed from dir, creating them on first use.
// This is the general (non-coding-agent) analog of `legant guard init`: it makes a
// self-contained offline trust domain so apply/mint/show/revoke need no server or
// database. The private key is a LOCAL key — in a real deployment tokens come from
// a token-exchange against your Legant issuer and the JWKS/feed are its endpoints.
func EnsureSetup(dir, issuer string, now time.Time) (*Setup, error) {
	if issuer == "" {
		issuer = ccguard.DefaultIssuer
	}
	if dir == "" {
		dir = ".legant"
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, "key.pem")
	jwksPath := filepath.Join(dir, "jwks.json")
	feedPath := filepath.Join(dir, "feed.jwt")

	created := false
	key, err := ccguard.LoadPrivateKey(keyPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		key, err = legantcrypto.GenerateRSAKey(2048)
		if err != nil {
			return nil, err
		}
		if err := ccguard.SavePrivateKey(keyPath, key); err != nil {
			return nil, err
		}
		jwks, err := ccguard.BuildJWKS(ccguard.LocalKID, &key.PublicKey)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(jwksPath, jwks, 0o600); err != nil {
			return nil, err
		}
		feed, err := ccguard.BuildSignedFeed(nil, 1, issuer, ccguard.LocalKID, key, 14*24*time.Hour, now)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(feedPath, []byte(feed), 0o600); err != nil {
			return nil, err
		}
		created = true
	}
	jb, err := os.ReadFile(jwksPath)
	if err != nil {
		return nil, err
	}
	keys, err := sdk.ParseJWKS(jb)
	if err != nil {
		return nil, err
	}
	return &Setup{
		Dir: dir, Issuer: issuer, FeedPath: feedPath, created: created,
		Signer: delegation.NewSigner(issuer, ccguard.LocalKID, key), Keys: keys,
	}, nil
}

// Created reports whether EnsureSetup just bootstrapped the directory.
func (s *Setup) Created() bool { return s.created }

// Change is one entry in an apply diff.
type Change struct {
	Name     string
	File     string
	Action   string // "create" | "update" | "unchanged"
	Subject  string
	Agent    string // leaf actor
	Audience string
}

// ApplyResult is the outcome of reconciling a grants file into a setup dir.
type ApplyResult struct {
	Changes []Change
	Orphans []string // token files in the dir not in the declared set
	Minted  int
}

// Apply reconciles the declared grants into the setup dir: it mints a signed token
// per grant (and per declared sub-delegation), writing one file each, and reports a
// created/updated/unchanged diff against what is already there. It is idempotent —
// a grant whose declared shape matches the existing token is left untouched unless
// force is set — so re-applying an unchanged file is a no-op.
func (f *File) Apply(s *Setup, force bool, now time.Time) (*ApplyResult, error) {
	res := &ApplyResult{}
	declared := map[string]bool{}
	for i, g := range f.Grants {
		_, nodes, err := f.buildTree(g, i, now)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", g.label(i), err)
		}
		for _, n := range nodes {
			declared[n.file] = true
			path := filepath.Join(s.Dir, n.file)
			want := fingerprintGrant(n.grant, n.audience)
			action := "create"
			if existing, err := os.ReadFile(path); err == nil {
				if fingerprintToken(string(existing)) == want {
					action = "unchanged"
				} else {
					action = "update"
				}
			}
			leaf := n.grant.Delegatee
			ch := Change{Name: g.label(i), File: n.file, Action: action,
				Subject: n.grant.RootDelegator(), Agent: leaf, Audience: n.audience}
			if action != "unchanged" || force {
				tok, _, err := ccguard.MintGrant(s.Signer, n.grant, n.audience, now)
				if err != nil {
					return nil, fmt.Errorf("%s: mint: %w", g.label(i), err)
				}
				if err := os.WriteFile(path, []byte(tok), 0o600); err != nil {
					return nil, err
				}
				res.Minted++
				if action == "unchanged" {
					action = "update" // forced re-mint
					ch.Action = action
				}
			}
			res.Changes = append(res.Changes, ch)
		}
	}
	// Surface token files in the dir that the declared set no longer covers.
	entries, _ := os.ReadDir(s.Dir)
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".jwt") || n == "feed.jwt" || declared[n] {
			continue
		}
		res.Orphans = append(res.Orphans, n)
	}
	sort.Strings(res.Orphans)
	return res, nil
}

// Prune deletes orphaned token files and revokes their token ids on the feed, so
// `apply --prune` makes the dir match the file exactly (removed grants are killed,
// not just abandoned).
func (s *Setup) Prune(orphans []string, now time.Time) (int, error) {
	revoked := 0
	for _, n := range orphans {
		path := filepath.Join(s.Dir, n)
		if b, err := os.ReadFile(path); err == nil {
			if jti := ccguard.JTIOf(strings.TrimSpace(string(b))); jti != "" {
				if _, err := ccguard.RevokeJTI(s.Dir, jti, now); err == nil {
					revoked++
				}
			}
		}
		_ = os.Remove(path)
	}
	return revoked, nil
}

// Match is one grant that authorizes a queried action in WhoCan.
type Match struct {
	Name       string
	Provenance string
	Audience   string
	// TimeBoxed is set when the grant only permits the action inside a time window
	// that is NOT open at the evaluation instant — so it is structurally capable but
	// blocked right now. The reviewer still needs to see it.
	TimeBoxed bool
}

// WhoCan answers "which declared grants would permit this action?" by minting each
// grant in memory and running the SAME offline verify+authorize a resource server
// runs — so the answer is exactly what production would decide, not a re-implemented
// guess. An empty Resource/Tool/etc. on the action skips that dimension.
//
// Authorization is time-sensitive, but a reviewer asking "who can touch finance?"
// should not have a structurally-capable grant hidden just because they ran the
// query after hours. So a grant that passes every dimension EXCEPT its time window
// is still returned, flagged TimeBoxed.
func (f *File) WhoCan(s *Setup, action sdk.Action, now time.Time) ([]Match, error) {
	var matches []Match
	for i, g := range f.Grants {
		_, nodes, err := f.buildTree(g, i, now)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", g.label(i), err)
		}
		for _, n := range nodes {
			prov, ok, err := f.authorizeNode(s, n.grant, n.audience, action, now, false)
			if err != nil {
				return nil, err
			}
			if ok {
				matches = append(matches, Match{Name: g.label(i), Provenance: prov, Audience: n.audience})
				continue
			}
			// Retry with the time window stripped: if it now passes, the only thing
			// blocking it is the window being closed right now.
			if n.grant.Constraints.TimeWindow != nil {
				prov, ok, err := f.authorizeNode(s, n.grant, n.audience, action, now, true)
				if err != nil {
					return nil, err
				}
				if ok {
					matches = append(matches, Match{Name: g.label(i), Provenance: prov, Audience: n.audience, TimeBoxed: true})
				}
			}
		}
	}
	return matches, nil
}

// authorizeNode mints a node's token (optionally with its time window dropped) and
// runs the real SDK verify+authorize, returning the provenance and whether it passed.
func (f *File) authorizeNode(s *Setup, g *delegation.Grant, audience string, action sdk.Action, now time.Time, dropTimeWindow bool) (string, bool, error) {
	mintGrant := g
	if dropTimeWindow {
		clone := *g
		c := clone.Constraints
		c.TimeWindow = nil
		clone.Constraints = c
		mintGrant = &clone
		action.At = time.Time{}
	}
	tok, _, err := ccguard.MintGrant(s.Signer, mintGrant, audience, now)
	if err != nil {
		return "", false, err
	}
	claims, err := sdk.NewVerifier(s.Issuer, audience, s.Keys).Verify(tok)
	if err != nil {
		return "", false, nil
	}
	if err := claims.Authorize(action); err != nil {
		return "", false, nil
	}
	return claims.Provenance(), true, nil
}

// ---- fingerprints (idempotency) -------------------------------------------

// fingerprintGrant renders a stable signature of a grant's authority-defining
// fields (everything except the per-mint jti/iat/exp), so a re-apply can tell
// "same authority" from "changed authority".
func fingerprintGrant(g *delegation.Grant, audience string) string {
	var actors []string
	actors = append(actors, g.RootDelegator())
	actors = append(actors, g.ActorChainRootToLeaf()...)
	return canonical(map[string]any{
		"sub":   actors[0],
		"chain": actors,
		"scope": sortedCopy(g.Scopes),
		"aud":   audience,
		"cnst":  canonicalConstraints(g.Constraints),
	})
}

// fingerprintToken decodes an already-written token and renders the same signature.
func fingerprintToken(tok string) string {
	parts := strings.Split(strings.TrimSpace(tok), ".")
	if len(parts) < 2 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		Sub   string                  `json:"sub"`
		Aud   json.RawMessage         `json:"aud"`
		Scope string                  `json:"scope"`
		Act   *actClaim               `json:"act"`
		Cnst  *delegation.Constraints `json:"cnst"`
	}
	if json.Unmarshal(raw, &c) != nil {
		return ""
	}
	chain := []string{c.Sub}
	var rev []string
	for a := c.Act; a != nil; a = a.Act {
		rev = append(rev, a.Sub)
	}
	for i := len(rev) - 1; i >= 0; i-- {
		chain = append(chain, rev[i])
	}
	var cnst delegation.Constraints
	if c.Cnst != nil {
		cnst = *c.Cnst
	}
	return canonical(map[string]any{
		"sub":   c.Sub,
		"chain": chain,
		"scope": sortedCopy(strings.Fields(c.Scope)),
		"aud":   audString(c.Aud),
		"cnst":  canonicalConstraints(cnst),
	})
}

type actClaim struct {
	Sub string    `json:"sub"`
	Act *actClaim `json:"act"`
}

func audString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var ss []string
	if json.Unmarshal(raw, &ss) == nil {
		sort.Strings(ss)
		return strings.Join(ss, ",")
	}
	return string(raw)
}

func canonicalConstraints(c delegation.Constraints) map[string]any {
	m := map[string]any{
		"categories": sortedCopy(c.Categories),
		"tools":      sortedCopy(c.Tools),
		"resources":  sortedCopy(c.Resources),
	}
	if c.MaxAmount != nil {
		m["max_amount"] = *c.MaxAmount
	}
	if c.TimeWindow != nil {
		m["time_window"] = map[string]any{
			"weekdays": c.TimeWindow.Weekdays, "start": c.TimeWindow.StartMin,
			"end": c.TimeWindow.EndMin, "tz": c.TimeWindow.TZ,
		}
	}
	return m
}

func canonical(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func sortedCopy(s []string) []string {
	if len(s) == 0 {
		return []string{}
	}
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

// sanitize turns a principal/agent label into a safe filename fragment.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "grant"
	}
	return out
}

// StarterYAML is the commented template `legant init grants` writes.
const StarterYAML = `# legant.grants.yaml — declarative delegated authority, reviewable in a PR.
# Lint:  legant lint -f legant.grants.yaml
# Apply: legant apply -f legant.grants.yaml      (mints signed tokens into .legant/)
# Ask:   legant who-can -f legant.grants.yaml --scope warehouse:query --resource finance
version: 1

# Default audience (the resource server these tokens are for). Override per grant.
audience: https://api.example.internal
defaults:
  ttl: 1h

grants:
  # "user:alice delegates to her analytics copilot the right to query the
  #  warehouse, but only sales+finance schemas, business hours, for one hour."
  - name: alice-analytics
    principal: user:alice
    agent: agent:analytics-copilot
    scopes: [warehouse:query]
    audience: warehouse://analytics
    ttl: 1h
    constraints:
      resources: [sales, finance]          # RFC 8707 audiences the token may target
      time_window: { weekdays: [1,2,3,4,5], start: "09:00", end: "17:00", tz: UTC }

  # A spend-capped payments agent, with an attenuated sub-agent that can do less.
  - name: payments-bot
    principal: user:treasury
    agent: agent:payments
    scopes: [transfer:prepare]
    audience: https://treasury.example.internal
    constraints:
      max_amount: 5000
      categories: [vendor, payroll]
    delegate:
      - agent: agent:reconciler
        scopes: [transfer:prepare]
        constraints:
          max_amount: 500                  # the child can only ever do LESS
`
