package ccguard

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// InstallOptions configures `legant guard install`.
type InstallOptions struct {
	Dir       string   // guard setup dir (auto-created if absent); default per-project, outside the project
	Project   string   // project root the agent works in
	Role      string   // rule set to wire: reviewer|builder|open|operator (default open)
	Binary    string   // absolute path to the legant binary (default: this executable)
	Tools     []string // claude-code|codex|opencode; empty → auto-detect installed agents
	UserScope bool     // write user-global config where supported (codex/opencode)
}

// InstallResult describes one config the installer wrote (or would remove).
type InstallResult struct {
	Tool string
	Path string
	Note string
}

// Install ensures a guard setup exists and wires the guard hook into each
// selected (or auto-detected) coding agent. It is idempotent: re-running
// replaces the Legant block rather than duplicating it, and never clobbers other
// settings in a shared config file.
func Install(opts InstallOptions) ([]InstallResult, error) {
	project := absOrSame(opts.Project)
	dir := opts.Dir
	if dir == "" {
		dir = DefaultGuardDir(project)
	}
	dir = absOrSame(dir)

	// Ensure the guard's key/JWKS/feed/role-tokens exist (init on first install).
	if _, err := os.Stat(filepath.Join(dir, "jwks.json")); err != nil {
		if _, err := InitLocal(dir, project, 720*time.Hour, time.Now()); err != nil {
			return nil, fmt.Errorf("set up guard dir: %w", err)
		}
	}
	role := opts.Role
	if role == "" {
		role = "open"
	}
	tokenFile := filepath.Join(dir, role+".jwt")
	if _, err := os.Stat(tokenFile); err != nil {
		return nil, fmt.Errorf("role token %q not found in %s (roles: reviewer, builder, open, operator)", role, dir)
	}
	binary := opts.Binary
	if binary == "" {
		if exe, err := os.Executable(); err == nil {
			binary = exe
		} else {
			binary = "legant"
		}
	}

	env := guardEnv(dir, tokenFile)
	cmd := inlineEnvCommand(env, binary)

	tools := opts.Tools
	if len(tools) == 0 {
		tools = detectTools(project)
	}
	if len(tools) == 0 {
		return nil, fmt.Errorf("no supported agent detected — pass --tool claude-code|codex|opencode")
	}

	var out []InstallResult
	for _, t := range tools {
		var (
			r   InstallResult
			err error
		)
		switch t {
		case "claude-code":
			r, err = installClaudeCode(project, cmd)
		case "codex":
			r, err = installCodex(project, cmd, opts.UserScope)
		case "opencode":
			r, err = installOpencode(project, env, binary, opts.UserScope)
		default:
			err = fmt.Errorf("unknown tool %q (want claude-code|codex|opencode)", t)
		}
		if err != nil {
			return out, fmt.Errorf("%s: %w", t, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// Uninstall removes the Legant guard hook from every known config location
// (project and user scope) for the given project. Best-effort and idempotent.
func Uninstall(project string) []InstallResult {
	project = absOrSame(project)
	home, _ := os.UserHomeDir()
	cfg, _ := os.UserConfigDir()
	var out []InstallResult
	for _, p := range []string{
		filepath.Join(project, ".claude", "settings.local.json"),
		filepath.Join(project, ".codex", "hooks.json"),
		filepath.Join(home, ".codex", "hooks.json"),
	} {
		if removeLegantBlock(p) {
			out = append(out, InstallResult{Tool: "hook", Path: p, Note: "removed Legant PreToolUse block"})
		}
	}
	for _, p := range []string{
		filepath.Join(project, ".opencode", "plugin", "legant-guard.ts"),
		filepath.Join(cfg, "opencode", "plugin", "legant-guard.ts"),
	} {
		if err := os.Remove(p); err == nil {
			out = append(out, InstallResult{Tool: "opencode", Path: p, Note: "removed plugin"})
		}
	}
	return out
}

func guardEnv(dir, tokenFile string) map[string]string {
	return map[string]string{
		"LEGANT_GUARD_TOKEN_FILE": tokenFile,
		"LEGANT_GUARD_JWKS":       filepath.Join(dir, "jwks.json"),
		"LEGANT_GUARD_FEED":       filepath.Join(dir, "feed.jwt"),
		"LEGANT_GUARD_AUDIT":      filepath.Join(dir, "audit.jsonl"),
		"LEGANT_GUARD_OVERLAY":    filepath.Join(dir, "overlay.json"),
		"LEGANT_GUARD_ISSUER":     DefaultIssuer,
		"LEGANT_GUARD_AUDIENCE":   DefaultAudience,
	}
}

// OverlayPath returns the overlay file location for a guard dir.
func OverlayPath(dir string) string { return filepath.Join(dir, "overlay.json") }

// inlineEnvCommand renders a shell command that runs `legant guard check` with
// the guard env inlined, so a hook config needs no separate environment setup.
func inlineEnvCommand(env map[string]string, binary string) string {
	var b strings.Builder
	b.WriteString("env")
	for _, k := range sortedKeys(env) {
		fmt.Fprintf(&b, " %s=%s", k, shellQuote(env[k]))
	}
	fmt.Fprintf(&b, " %s guard check", shellQuote(binary))
	return b.String()
}

// detectTools returns the agents that appear installed (binary on PATH or a
// config dir present).
func detectTools(project string) []string {
	home, _ := os.UserHomeDir()
	cfg, _ := os.UserConfigDir()
	onPath := func(n string) bool { _, err := exec.LookPath(n); return err == nil }
	isDir := func(p string) bool { fi, err := os.Stat(p); return err == nil && fi.IsDir() }
	var t []string
	if onPath("claude") || isDir(filepath.Join(project, ".claude")) {
		t = append(t, "claude-code")
	}
	if onPath("codex") || isDir(filepath.Join(home, ".codex")) {
		t = append(t, "codex")
	}
	if onPath("opencode") || isDir(filepath.Join(cfg, "opencode")) || isDir(filepath.Join(project, ".opencode")) {
		t = append(t, "opencode")
	}
	return t
}

func installClaudeCode(project, cmd string) (InstallResult, error) {
	p := filepath.Join(project, ".claude", "settings.local.json")
	if err := mergePreToolUse(p, "*", cmd); err != nil {
		return InstallResult{}, err
	}
	return InstallResult{Tool: "claude-code", Path: p, Note: "PreToolUse hook (all tools) — denies via exit 2, survives bypass mode"}, nil
}

func installCodex(project, cmd string, userScope bool) (InstallResult, error) {
	p := filepath.Join(project, ".codex", "hooks.json")
	if userScope {
		home, _ := os.UserHomeDir()
		p = filepath.Join(home, ".codex", "hooks.json")
	}
	// Codex PreToolUse exposes Bash, apply_patch (edits), and MCP tools.
	if err := mergePreToolUse(p, "^(Bash|apply_patch|mcp__.*)$", cmd); err != nil {
		return InstallResult{}, err
	}
	return InstallResult{Tool: "codex", Path: p, Note: "PreToolUse hook (Bash/apply_patch/mcp) — denies via exit 2, survives --yolo"}, nil
}

func installOpencode(project string, env map[string]string, binary string, userScope bool) (InstallResult, error) {
	dir := filepath.Join(project, ".opencode", "plugin")
	if userScope {
		cfg, _ := os.UserConfigDir()
		dir = filepath.Join(cfg, "opencode", "plugin")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return InstallResult{}, err
	}
	p := filepath.Join(dir, "legant-guard.ts")
	if err := os.WriteFile(p, []byte(opencodePlugin(env, binary)), 0o644); err != nil {
		return InstallResult{}, err
	}
	return InstallResult{Tool: "opencode", Path: p, Note: "tool.execute.before plugin — denies by throwing"}, nil
}

// mergePreToolUse adds (or replaces) a Legant PreToolUse hook in a Claude-Code /
// Codex-style settings JSON, preserving any other settings. It refuses to touch a
// file that exists but is not valid JSON.
func mergePreToolUse(path, matcher, cmd string) error {
	root := map[string]any{}
	if b, err := os.ReadFile(path); err == nil {
		if e := json.Unmarshal(b, &root); e != nil {
			return fmt.Errorf("%s exists but is not valid JSON; fix or remove it first", path)
		}
	}
	hooks, _ := root["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	pre, _ := hooks["PreToolUse"].([]any)
	kept := make([]any, 0, len(pre)+1)
	for _, item := range pre {
		if !blockHasLegant(item) {
			kept = append(kept, item)
		}
	}
	kept = append(kept, map[string]any{
		"matcher": matcher,
		"hooks":   []any{map[string]any{"type": "command", "command": cmd}},
	})
	hooks["PreToolUse"] = kept
	root["hooks"] = hooks
	return writeJSONFile(path, root)
}

// removeLegantBlock strips Legant PreToolUse blocks from a settings JSON. Returns
// true if it changed the file.
func removeLegantBlock(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	root := map[string]any{}
	if json.Unmarshal(b, &root) != nil {
		return false
	}
	hooks, _ := root["hooks"].(map[string]any)
	pre, _ := hooks["PreToolUse"].([]any)
	var kept []any
	changed := false
	for _, item := range pre {
		if blockHasLegant(item) {
			changed = true
			continue
		}
		kept = append(kept, item)
	}
	if !changed {
		return false
	}
	if len(kept) == 0 {
		delete(hooks, "PreToolUse")
	} else {
		hooks["PreToolUse"] = kept
	}
	root["hooks"] = hooks
	_ = writeJSONFile(path, root)
	return true
}

func blockHasLegant(item any) bool {
	m, _ := item.(map[string]any)
	hs, _ := m["hooks"].([]any)
	for _, h := range hs {
		hm, _ := h.(map[string]any)
		if c, _ := hm["command"].(string); strings.Contains(c, "guard check") && strings.Contains(c, "LEGANT_GUARD") {
			return true
		}
	}
	return false
}

func writeJSONFile(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// opencodePlugin renders the TypeScript plugin that gates opencode tool calls by
// shelling out to `legant guard check` and throwing on a deny (exit 2).
func opencodePlugin(env map[string]string, binary string) string {
	envJSON, _ := json.MarshalIndent(env, "", "  ")
	return `// legant-guard.ts — generated by ` + "`legant guard install`" + `. Gates opencode tool
// calls through the Legant guard: it shells out to the guard, which denies with
// exit code 2, and the plugin throws to block the tool. Safe to commit or delete.
import { spawnSync } from "node:child_process"

const BIN = ` + jsonString(binary) + `
const ENV = ` + string(envJSON) + `

// opencode tool name -> the canonical name the Legant guard understands.
const MAP: Record<string, string> = {
  bash: "Bash", read: "Read", write: "Write", edit: "Edit", glob: "Glob",
  grep: "Grep", list: "LS", webfetch: "WebFetch", websearch: "WebSearch",
  apply_patch: "apply_patch", patch: "apply_patch",
}

export const LegantGuard = async () => ({
  "tool.execute.before": async (input: any, output: any) => {
    const tool = MAP[input.tool] ?? input.tool
    const event = JSON.stringify({
      hook_event_name: "PreToolUse",
      session_id: "opencode",
      cwd: process.cwd(),
      tool_name: tool,
      tool_input: output?.args ?? {},
    })
    const r = spawnSync(BIN, ["guard", "check"], {
      input: event,
      env: { ...process.env, ...ENV },
      timeout: 5000,
    })
    if (r.status === 2) {
      throw new Error((r.stderr?.toString() || "denied by Legant guard").trim())
    }
  },
})
`
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// shellQuote double-quotes a value for a POSIX shell command line.
func shellQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "\\`", `$`, `\$`).Replace(s) + `"`
}
