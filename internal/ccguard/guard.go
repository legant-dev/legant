// Package ccguard turns a Legant delegation token into a policy decision for
// every tool call Claude Code makes — Read, Write, Edit, Bash, WebFetch and MCP
// tools alike — enforced OFFLINE from the signed token. It is the local-machine
// analog of the MCP auth-gateway: where the gateway governs remote MCP tools,
// the guard governs Claude Code's built-in tools (the file reads/writes and
// shell commands an agent runs locally).
//
// It runs as a Claude Code PreToolUse hook: Claude Code writes the pending tool
// call to the hook's stdin as JSON, the guard authorizes it against a delegated
// "acting-for-Alice" token (scoped, time-boxed, attenuating across sub-agents,
// revocable via the signed feed), and writes a decision to stdout.
//
// Two design invariants:
//
//   - ADDITIVE DENIAL ONLY. The guard can only ever BLOCK a tool call (it exits
//     with code 2 — the hard block Claude Code honors BEFORE permission
//     evaluation, so it bites even in bypassPermissions/"YOLO" mode); on allow it
//     exits 0 with no output and defers to Claude Code's own permission system.
//     Installing the guard can only tighten what an agent may do, never loosen it.
//     This mirrors Legant's revocation feed, which can miss a revoke but can never
//     forge an authorization.
//   - SHELL IS A COARSE GRANT. fs.read/fs.write (Read/Write/Edit) are truly
//     path-contained. shell.exec (Bash) CANNOT be path-contained offline — an
//     allow-listed `cat`/`sed`/`python3`/redirect can touch any path, and no
//     command parser stops that soundly. For shell.exec the guarantees are the
//     command allow/deny lists, the catastrophic-command tripwires, best-effort
//     redirect containment, audit and revocation. A role that needs HARD
//     filesystem containment must NOT grant shell.exec (use the reviewer role) or
//     must run the agent in an OS sandbox. This is stated plainly, not hidden.
package ccguard

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/legant-dev/legant/sdk"
)

// denyAllSentinel equals the sentinel Legant puts in an allow-list intersected to
// nothing during re-delegation (see internal/delegation, sdk). Its presence in
// cnst.resources means that dimension was attenuated to "deny everything"; the
// guard fails CLOSED on it rather than ignoring it (which would fail OPEN).
const denyAllSentinel = "\x00legant:deny-all"

// HookInput is the PreToolUse event Claude Code writes to the hook's stdin.
// Only the fields the guard needs are modeled; unknown fields are ignored.
type HookInput struct {
	HookEventName string          `json:"hook_event_name"`
	SessionID     string          `json:"session_id"`
	Cwd           string          `json:"cwd"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
}

// Decision is the guard's internal verdict for one tool call.
type Decision struct {
	Block  bool   // true → the tool call is denied
	Reason string // human-readable reason (also fed back to the agent on a block)
	Verb   string // the abstract capability the call required, e.g. "fs.write"
	Target string // the concrete object, e.g. an absolute path or a command
	JTI    string // the delegation token id, for audit
	Prov   string // provenance, e.g. "user:alice -> agent:claude -> agent:reviewer"
}

// Guard authorizes Claude Code tool calls against a single delegation token.
type Guard struct {
	verifier    *sdk.Verifier
	feed        *SignedFeed // nil = no offline revocation source (TTL backstop only)
	token       string
	denyAll     string   // non-empty → deny every call (fail-closed mode)
	selfProtect []string // absolute paths of the guard's OWN trust material (always denied)
	overlay     *Overlay // deny-only local restriction layer (nil = none)
	now         func() time.Time
}

// Config holds everything the guard needs to make decisions, normally sourced
// from the LEGANT_GUARD_* environment by LoadConfigFromEnv.
type Config struct {
	Token    string                    // the delegation token (the agent's authority)
	Issuer   string                    // expected token issuer
	Audience string                    // the guard's own resource-server identity
	Keys     map[string]*rsa.PublicKey // issuer JWKS (verifies token + feed)
	Feed     *SignedFeed               // optional offline revocation feed
	// SelfProtect lists absolute paths of the guard's own files (token, JWKS,
	// feed, key, audit, .claude settings). The guard ALWAYS denies fs.read/fs.write
	// to them regardless of scope/roots, so an agent cannot tamper with its own
	// leash (roll back revocation, read the signing key, repoint the token).
	SelfProtect []string
	// DenyAll, when non-empty, makes every decision a block with this reason. Set
	// when a configured revocation feed could not be loaded (tamper/fail-closed).
	DenyAll string
	// Warn is a non-fatal advisory for stderr.
	Warn string
	// Overlay is an optional deny-only local restriction layer applied on top of
	// the token. It can only tighten; nil/empty changes nothing.
	Overlay *Overlay
}

// NewGuard builds a guard from a config.
func NewGuard(c Config) *Guard {
	return &Guard{
		verifier:    sdk.NewVerifier(c.Issuer, c.Audience, c.Keys),
		feed:        c.Feed,
		token:       c.Token,
		denyAll:     c.DenyAll,
		selfProtect: c.SelfProtect,
		overlay:     c.Overlay,
		now:         time.Now,
	}
}

// Decide authorizes one Claude Code tool call, entirely offline. It fails CLOSED:
// any verification or parsing failure blocks the call.
func (g *Guard) Decide(in HookInput) Decision {
	act := classify(in.ToolName, in.ToolInput, in.Cwd)

	// Fail-closed mode (e.g. a configured revocation feed could not be loaded).
	if g.denyAll != "" {
		return Decision{Block: true, Reason: g.denyAll, Verb: act.verb, Target: act.target}
	}

	claims, err := g.verifier.Verify(g.token)
	if err != nil {
		return Decision{Block: true, Reason: "delegation token rejected: " + err.Error(), Verb: act.verb, Target: act.target}
	}
	dec := Decision{Verb: act.verb, Target: act.target, JTI: claims.ID, Prov: claims.Provenance()}

	// Tier-B revocation: the token id is on the signed kill-list (offline).
	if g.feed != nil && claims.ID != "" && g.feed.IsRevoked(claims.ID) {
		return block(dec, "delegation revoked (token %s is on the signed revocation feed)", short(claims.ID))
	}

	// Time window — the authority may be time-boxed ("only for the next hour").
	if claims.Constraints != nil && claims.Constraints.TimeWindow != nil {
		if !claims.Constraints.TimeWindow.Allows(g.now()) {
			return block(dec, "outside the delegated time window for this session")
		}
	}

	// Capability scope — the verb this tool requires must be granted. "*" is a
	// wildcard for a deliberately broad role.
	if !hasScopeIn(claims.Scope, act.verb) && !hasScopeIn(claims.Scope, "*") {
		return block(dec, "capability %q is not granted to this agent (token grants: %s)", act.verb, scopeOrNone(claims.Scope))
	}

	// Tool allow-list (cnst.tools) and deny-list (cnst.resources "deny-tool:").
	if claims.Constraints != nil && len(claims.Constraints.Tools) > 0 && !containsStr(claims.Constraints.Tools, in.ToolName) {
		return block(dec, "tool %q is not in this agent's allowed tool-list", in.ToolName)
	}
	if containsStr(g.withOverlay(resourceValues(claims, "deny-tool:"), overlayTools), in.ToolName) {
		return block(dec, "tool %q is explicitly denied to this agent", in.ToolName)
	}

	// Per-verb fine-grained checks.
	switch act.verb {
	case "fs.read", "fs.write":
		if reason, ok := g.checkPaths(claims, act.paths, act.cwd); !ok {
			return block(dec, "%s", reason)
		}
	case "shell.exec":
		if reason, ok := g.checkCommand(claims, act.target, act.cwd); !ok {
			return block(dec, "%s", reason)
		}
	case "net.fetch":
		if reason, ok := g.checkHost(claims, act.target); !ok {
			return block(dec, "%s", reason)
		}
	}

	dec.Reason = "allowed"
	return dec
}

func block(d Decision, format string, args ...any) Decision {
	d.Block = true
	d.Reason = fmt.Sprintf(format, args...)
	return d
}

// classified is the abstract operation a tool call maps to.
type classified struct {
	verb   string   // capability required, e.g. "fs.write", "shell.exec"
	target string   // primary object: an absolute path, a command, or a URL
	paths  []string // all filesystem paths the call touches (absolute, cleaned)
	cwd    string   // the session working directory (resolves relative path roots)
}

// classify maps a Claude Code tool + its input to an abstract capability and the
// concrete object(s) it acts on. Unknown tools map to "other" — fail closed.
func classify(tool string, rawInput json.RawMessage, cwd string) classified {
	res := classifyVerb(tool, rawInput, cwd)
	res.cwd = cwd
	return res
}

// classifyVerb maps a tool name (across Claude Code, Codex, and opencode) and its
// input to a capability + the object(s) it touches. Tool names are matched
// case-insensitively, and both snake_case (file_path) and camelCase (filePath)
// argument keys are accepted, so one engine serves all three agents' adapters.
func classifyVerb(tool string, rawInput json.RawMessage, cwd string) classified {
	if strings.HasPrefix(strings.ToLower(tool), "mcp__") {
		return classified{verb: "mcp.call", target: tool}
	}
	var in struct {
		FilePath      string `json:"file_path"`
		FilePathCamel string `json:"filePath"` // opencode
		Path          string `json:"path"`
		NotebookP     string `json:"notebook_path"`
		Command       string `json:"command"`
		URL           string `json:"url"`
		PatchText     string `json:"patchText"` // opencode apply_patch
	}
	_ = json.Unmarshal(rawInput, &in)

	filePath := in.FilePath
	if filePath == "" {
		filePath = in.FilePathCamel
	}
	patch := in.Command // Codex apply_patch carries the patch in `command`
	if patch == "" {
		patch = in.PatchText
	}
	pathOf := func(p string) []string {
		if p = absClean(cwd, p); p == "" {
			return nil
		}
		return []string{p}
	}

	switch strings.ToLower(tool) {
	case "read", "notebookread":
		p := filePath
		if p == "" {
			p = in.NotebookP
		}
		return classified{verb: "fs.read", target: absClean(cwd, p), paths: pathOf(p)}
	case "glob", "grep", "ls", "list", "list_dir":
		p := in.Path
		if p == "" {
			p = cwd
		}
		return classified{verb: "fs.read", target: absClean(cwd, p), paths: pathOf(p)}
	case "write", "edit", "multiedit":
		return classified{verb: "fs.write", target: absClean(cwd, filePath), paths: pathOf(filePath)}
	case "notebookedit":
		return classified{verb: "fs.write", target: absClean(cwd, in.NotebookP), paths: pathOf(in.NotebookP)}
	case "apply_patch", "patch":
		// Codex/opencode patch tool: extract every file the patch touches.
		paths := applyPatchPaths(patch, cwd)
		return classified{verb: "fs.write", target: "apply_patch", paths: paths}
	case "bash", "bashoutput", "shell":
		return classified{verb: "shell.exec", target: strings.TrimSpace(in.Command)}
	case "webfetch", "websearch":
		return classified{verb: "net.fetch", target: in.URL}
	case "task":
		return classified{verb: "agent.spawn", target: tool}
	default:
		return classified{verb: "other", target: tool}
	}
}

// checkPaths enforces, in order: (1) DENY rules — the guard's own files
// (selfProtect), explicit cnst "deny-path:" entries, and the deny-all sentinel —
// which block regardless of scope or allow-roots ("allow everything EXCEPT X");
// then (2) ALLOW roots — cnst "path:" entries; empty means no allow-restriction.
// Targets and roots are resolved through symlinks before the lexical containment
// check, so neither "../" nor a symlink inside a root can escape it.
func (g *Guard) checkPaths(claims *sdk.Claims, paths []string, cwd string) (string, bool) {
	if containsStr(claimResources(claims), denyAllSentinel) {
		return "filesystem access is fully restricted by this delegation", false
	}

	denyRoots := append([]string(nil), g.selfProtect...)
	denyRoots = append(denyRoots, absResolve(g.withOverlay(resourceValues(claims, "deny-path:"), overlayPaths), cwd)...)
	for _, p := range paths {
		if contained(realPath(p), realPaths(denyRoots)) {
			return fmt.Sprintf("path %q is explicitly denied to this agent", p), false
		}
	}

	allowRoots := resourceValues(claims, "path:")
	if len(allowRoots) == 0 {
		return "", true // no allow-restriction (deny rules above still applied)
	}
	if len(paths) == 0 {
		return "could not determine the target path for an allow-root check; refusing", false
	}
	absAllow := realPaths(absResolve(allowRoots, cwd))
	for _, p := range paths {
		if !contained(realPath(p), absAllow) {
			return fmt.Sprintf("path %q is outside this agent's allowed roots %v", p, allowRoots), false
		}
	}
	return "", true
}

// checkCommand screens a Bash command. It is best-effort by design (see the
// package doc): the catastrophic-command tripwires and deny-list always apply,
// the cmd allow-list applies when set, and redirect write-targets are run through
// the same path containment as Write — but an allow-listed reader/interpreter can
// still touch arbitrary paths, which is why shell.exec is a coarse grant.
func (g *Guard) checkCommand(claims *sdk.Claims, command, cwd string) (string, bool) {
	if containsStr(claimResources(claims), denyAllSentinel) {
		return "command execution is fully restricted by this delegation", false
	}
	if why, bad := catastrophic(command); bad {
		return "command blocked: " + why + " (refused even with shell.exec)", false
	}

	exes := commandExecutables(command)
	denied := g.withOverlay(resourceValues(claims, "deny-cmd:"), overlayCmds)
	for _, e := range exes {
		if containsStr(denied, e) {
			return fmt.Sprintf("command %q is explicitly denied to this agent", e), false
		}
	}
	if allowed := resourceValues(claims, "cmd:"); len(allowed) > 0 {
		if len(exes) == 0 {
			return "command could not be parsed for an allow-list check; refusing", false
		}
		for _, e := range exes {
			if !containsStr(allowed, e) {
				return fmt.Sprintf("command %q is not in this agent's allowed commands %v", e, allowed), false
			}
		}
	}
	// Best-effort containment: a redirect that WRITES a file outside the allowed
	// roots (or into the guard's own files) is refused.
	if targets := redirectTargets(command); len(targets) > 0 {
		if reason, ok := g.checkPaths(claims, absResolve(targets, cwd), cwd); !ok {
			return "shell redirect " + reason, false
		}
	}
	return "", true
}

// checkHost enforces host rules for net.fetch: the deny-all sentinel and
// "deny-host:" entries block; "host:" entries, when present, allow-list.
func (g *Guard) checkHost(claims *sdk.Claims, rawURL string) (string, bool) {
	if containsStr(claimResources(claims), denyAllSentinel) {
		return "network access is fully restricted by this delegation", false
	}
	host := hostOf(rawURL)
	for _, h := range g.withOverlay(resourceValues(claims, "deny-host:"), overlayHosts) {
		if host == h || strings.HasSuffix(host, "."+h) {
			return fmt.Sprintf("host %q is explicitly denied to this agent", host), false
		}
	}
	allowed := resourceValues(claims, "host:")
	if len(allowed) == 0 {
		return "", true
	}
	for _, h := range allowed {
		if host == h || strings.HasSuffix(host, "."+h) {
			return "", true
		}
	}
	return fmt.Sprintf("host %q is not in this agent's allowed hosts %v", host, allowed), false
}

// resourceValues returns cnst.resources entries carrying the given scheme prefix
// (e.g. "path:"), with the prefix stripped.
func resourceValues(claims *sdk.Claims, prefix string) []string {
	var out []string
	for _, r := range claimResources(claims) {
		if strings.HasPrefix(r, prefix) {
			out = append(out, strings.TrimPrefix(r, prefix))
		}
	}
	return out
}

func claimResources(claims *sdk.Claims) []string {
	if claims == nil || claims.Constraints == nil {
		return nil
	}
	return claims.Constraints.Resources
}

func scopeOrNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(none)"
	}
	return s
}

func short(s string) string {
	if len(s) > 10 {
		return s[:10] + "…"
	}
	return s
}

func containsStr(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

// withOverlay appends the overlay's deny rules (selected by sel) to a token's
// deny list. The overlay can ONLY ADD denials — it never removes a token rule —
// so this can only tighten. A nil overlay returns the token list unchanged, so
// the overlay layer cannot regress existing behavior.
func (g *Guard) withOverlay(tokenList []string, sel func(*Overlay) []string) []string {
	if g.overlay == nil {
		return tokenList
	}
	extra := sel(g.overlay)
	if len(extra) == 0 {
		return tokenList
	}
	return append(append([]string(nil), tokenList...), extra...)
}

func overlayPaths(o *Overlay) []string { return o.DenyPaths }
func overlayCmds(o *Overlay) []string  { return o.DenyCmds }
func overlayHosts(o *Overlay) []string { return o.DenyHosts }
func overlayTools(o *Overlay) []string { return o.DenyTools }
