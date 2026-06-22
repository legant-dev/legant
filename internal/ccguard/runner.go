package ccguard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/legant-dev/legant/sdk"
)

// Environment variables that configure the guard hook. Providing a token is what
// switches the guard ON; with no token the hook is a no-op (it allows everything
// and defers entirely to Claude Code), so it is safe to leave installed.
const (
	EnvToken     = "LEGANT_GUARD_TOKEN"      // the delegation token (inline)
	EnvTokenFile = "LEGANT_GUARD_TOKEN_FILE" // …or a file to read it from
	EnvJWKS      = "LEGANT_GUARD_JWKS"       // path to the issuer JWKS (public keys)
	EnvIssuer    = "LEGANT_GUARD_ISSUER"     // expected token issuer
	EnvAudience  = "LEGANT_GUARD_AUDIENCE"   // the guard's resource-server identity
	EnvFeed      = "LEGANT_GUARD_FEED"       // signed revocation feed; configured-but-unloadable fails CLOSED
	EnvAudit     = "LEGANT_GUARD_AUDIT"      // path to append decision audit JSONL (optional)
	EnvOverlay   = "LEGANT_GUARD_OVERLAY"    // deny-only overlay file (default <guarddir>/overlay.json)
	// Connected mode: stream each decision to a running Legant server's live console.
	EnvLiveURL   = "LEGANT_GUARD_LIVE_URL"   // POST .../admin/live/ingest (optional)
	EnvLiveToken = "LEGANT_GUARD_LIVE_TOKEN" // shared ingest secret
	EnvSource    = "LEGANT_GUARD_SOURCE"     // label for the console (default "claude-code")
)

// Defaults for the offline/local setup produced by `legant guard init`.
const (
	DefaultIssuer   = "https://legant.local"
	DefaultAudience = "legant:claude-code"
)

// LoadConfigFromEnv builds a guard Config from the LEGANT_GUARD_* environment.
// The returned enabled flag is false when no token is configured: in that case
// the hook should allow everything (the guard is opt-in). An error means the
// guard is configured but its key material could not be loaded — a
// misconfiguration the caller surfaces without blocking the session.
func LoadConfigFromEnv() (cfg Config, enabled bool, err error) {
	token := os.Getenv(EnvToken)
	if token == "" {
		if f := os.Getenv(EnvTokenFile); f != "" {
			b, e := os.ReadFile(f)
			if e != nil {
				return Config{}, true, fmt.Errorf("read %s: %w", EnvTokenFile, e)
			}
			token = trimToken(string(b))
		}
	}
	if token == "" {
		return Config{}, false, nil // guard disabled
	}

	issuer := envOr(EnvIssuer, DefaultIssuer)
	audience := envOr(EnvAudience, DefaultAudience)

	jwksPath := os.Getenv(EnvJWKS)
	if jwksPath == "" {
		return Config{}, true, fmt.Errorf("%s is set but %s (the issuer JWKS) is not", EnvToken, EnvJWKS)
	}
	jb, err := os.ReadFile(jwksPath)
	if err != nil {
		return Config{}, true, fmt.Errorf("read JWKS %s: %w", jwksPath, err)
	}
	keys, err := sdk.ParseJWKS(jb)
	if err != nil {
		return Config{}, true, fmt.Errorf("parse JWKS %s: %w", jwksPath, err)
	}

	cfg = Config{Token: token, Issuer: issuer, Audience: audience, Keys: keys}

	// The guard's OWN trust material is always off-limits to the agent: protect the
	// JWKS, feed, token, audit, and the signing key, plus the directories holding
	// them, so an agent with fs.write inside its root cannot roll back its own
	// revocation, read the signing key, or repoint its token. (RunCheck adds the
	// session's .claude dir too, protecting settings.json from a repoint attack.)
	cfg.SelfProtect = protectPaths(jwksPath, os.Getenv(EnvFeed), os.Getenv(EnvTokenFile),
		os.Getenv(EnvAudit), filepath.Join(filepath.Dir(jwksPath), "key.pem"))

	// Revocation feed. "No feed configured" (env unset) means revocation is bounded
	// by the token's short TTL (Tier C). But a feed that IS configured yet cannot be
	// loaded (deleted, corrupted, expired, signature/version invalid) is a tamper or
	// staleness signal, so the guard fails CLOSED rather than silently disabling
	// revocation. Keep the feed fresh (re-run `guard init` / point at a live feed).
	if feedPath := os.Getenv(EnvFeed); feedPath != "" {
		feed, ferr := LoadSignedFeedFile(feedPath, issuer, keys)
		if ferr != nil {
			cfg.DenyAll = "revocation feed could not be loaded (failing closed): " + ferr.Error()
		} else {
			cfg.Feed = feed
		}
	}

	// Deny-only overlay (extra local restrictions). Default to <guarddir>/overlay.json
	// alongside the JWKS. A malformed overlay is a non-fatal warning — the signed
	// token still fully enforces — rather than a hard failure that bricks a session.
	overlayPath := os.Getenv(EnvOverlay)
	if overlayPath == "" {
		overlayPath = filepath.Join(filepath.Dir(jwksPath), "overlay.json")
	}
	if ov, oerr := LoadOverlay(overlayPath); oerr != nil {
		cfg.Warn = appendWarn(cfg.Warn, "deny overlay ignored ("+oerr.Error()+"); the signed token still enforces")
	} else {
		cfg.Overlay = ov
	}

	return cfg, true, nil
}

func appendWarn(cur, msg string) string {
	if cur == "" {
		return msg
	}
	return cur + "; " + msg
}

// protectPaths returns the absolute form of each non-empty path AND its parent
// directory, deduplicated — the set the guard refuses all filesystem access to.
func protectPaths(paths ...string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(p string) {
		if p == "" {
			return
		}
		if a, err := filepath.Abs(p); err == nil {
			p = a
		}
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		abs := p
		if a, err := filepath.Abs(p); err == nil {
			abs = a
		}
		add(abs)
		add(filepath.Dir(abs))
	}
	return out
}

// AuditRecord is one line of the guard's local decision log — the offline analog
// of the audit a server-side resource check would land in Legant's hash chain.
type AuditRecord struct {
	Time       string `json:"ts"`
	Session    string `json:"session,omitempty"`
	Tool       string `json:"tool"`
	Verb       string `json:"verb"`
	Target     string `json:"target,omitempty"`
	Decision   string `json:"decision"` // "allow" | "deny"
	Reason     string `json:"reason,omitempty"`
	JTI        string `json:"jti,omitempty"`
	Provenance string `json:"provenance,omitempty"`
}

// CheckResult is the outcome of one PreToolUse authorization. The caller turns a
// Block into the actual hook decision (a stderr reason + exit code 2 — the hard
// block honored even in bypassPermissions mode); an allow produces no output.
type CheckResult struct {
	Block  bool
	Reason string
}

// RunCheck is the body of `legant guard check`: it reads one PreToolUse event
// from r, authorizes it, appends an audit line, and reports whether to block.
// With NO token configured the guard is off (allow). With a token configured but
// its trust material broken, it fails CLOSED (Block=true) — a broken or tampered
// guard must not silently stop enforcing. It returns an error only when it cannot
// read the hook event at all (the caller then exits non-blocking so a broken pipe
// never bricks a session).
func RunCheck(r io.Reader) (CheckResult, error) {
	raw, err := io.ReadAll(io.LimitReader(r, 4<<20))
	if err != nil {
		return CheckResult{}, fmt.Errorf("read hook input: %w", err)
	}
	var in HookInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return CheckResult{}, fmt.Errorf("parse hook input: %w", err)
	}

	cfg, enabled, cerr := LoadConfigFromEnv()
	if cerr != nil {
		// A token IS configured but its trust material is broken (unreadable JWKS,
		// corrupt feed, …). That can be a tamper attempt → fail CLOSED.
		return CheckResult{Block: true, Reason: "guard misconfigured (failing closed): " + cerr.Error()}, nil
	}
	if !enabled {
		return CheckResult{}, nil // no token → guard off → allow (defer to Claude Code)
	}
	if cfg.Warn != "" {
		fmt.Fprintln(os.Stderr, "legant guard: "+cfg.Warn)
	}
	// Also protect the session's .claude settings from a repoint-the-token escape.
	if in.Cwd != "" {
		cfg.SelfProtect = append(cfg.SelfProtect, filepath.Join(in.Cwd, ".claude"))
	}

	dec := NewGuard(cfg).Decide(in)
	writeAudit(os.Getenv(EnvAudit), in, dec)
	reportDecision(in, dec) // connected mode: stream to /admin/live (best-effort)
	return CheckResult{Block: dec.Block, Reason: dec.Reason}, nil
}

// reportDecision streams one decision to a running Legant server's live console
// when LEGANT_GUARD_LIVE_URL is set. It is best-effort and tightly time-bounded:
// the report never affects the allow/deny outcome and adds at most a few hundred
// ms only when connected mode is configured.
func reportDecision(in HookInput, dec Decision) {
	url := os.Getenv(EnvLiveURL)
	if url == "" {
		return
	}
	decision := "ALLOW"
	if dec.Block {
		decision = "DENY"
	}
	subject, actor := splitProvenance(dec.Prov)
	tool := in.ToolName
	if dec.Target != "" {
		tool = in.ToolName + ": " + truncate(dec.Target, 80)
	}
	body, _ := json.Marshal(map[string]string{
		"decision": decision, "subject": subject, "actor": actor,
		"provenance": dec.Prov, "tool": tool, "reason": dec.Reason,
		"source": envOr(EnvSource, "claude-code"),
	})
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if t := os.Getenv(EnvLiveToken); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	client := &http.Client{Timeout: 800 * time.Millisecond}
	if resp, err := client.Do(req); err == nil {
		_ = resp.Body.Close()
	}
}

func splitProvenance(p string) (subject, actor string) {
	parts := strings.Split(p, " -> ")
	if len(parts) == 0 || parts[0] == "" {
		return "", ""
	}
	return parts[0], parts[len(parts)-1]
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func writeAudit(path string, in HookInput, dec Decision) {
	if path == "" {
		return
	}
	verdict := "allow"
	if dec.Block {
		verdict = "deny"
	}
	rec := AuditRecord{
		Time:       time.Now().UTC().Format(time.RFC3339),
		Session:    in.SessionID,
		Tool:       in.ToolName,
		Verb:       dec.Verb,
		Target:     dec.Target,
		Decision:   verdict,
		Reason:     dec.Reason,
		JTI:        dec.JTI,
		Provenance: dec.Prov,
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func trimToken(s string) string {
	// tokens are a single compact JWS; strip surrounding whitespace/newlines.
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\n', '\r':
		default:
			out = append(out, s[i])
		}
	}
	return string(out)
}
