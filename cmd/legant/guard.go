package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/legant-dev/legant/internal/ccguard"
)

// guardCmd is the Claude Code "guard": a PreToolUse hook that authorizes every
// tool call against a Legant delegation token, offline. See docs/CLAUDE_CODE.md.
func guardCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "guard",
		Short: "Authorize Claude Code tool calls from a Legant delegation token (PreToolUse hook)",
	}
	cmd.AddCommand(guardCheckCmd(), guardDemoCmd(), guardInitCmd(), guardMintCmd(), guardRevokeCmd(), guardShowCmd(),
		guardInstallCmd(), guardUninstallCmd(), guardDenyCmd(), guardAllowCmd(), guardRulesCmd(), guardUICmd())
	return cmd
}

func guardUICmd() *cobra.Command {
	var dir, project string
	var port int
	cmd := &cobra.Command{
		Use:   "ui",
		Short: "Open a local control panel to view roles and edit the deny overlay live",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return ccguard.RunUI(ctx, resolveGuardDir(dir, project), port)
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "guard setup dir (default: the per-project dir)")
	cmd.Flags().StringVar(&project, "project", ".", "project root")
	cmd.Flags().IntVar(&port, "port", 0, "loopback port (0 = pick a free one)")
	return cmd
}

// overlayFlags is shared by `guard deny` and `guard allow`.
type overlayFlags struct{ paths, cmds, hosts, tools []string }

func (f *overlayFlags) bind(c *cobra.Command) {
	c.Flags().StringArrayVar(&f.paths, "path", nil, "a path (repeatable)")
	c.Flags().StringArrayVar(&f.cmds, "cmd", nil, "a shell command name (repeatable)")
	c.Flags().StringArrayVar(&f.hosts, "host", nil, "a hostname (repeatable)")
	c.Flags().StringArrayVar(&f.tools, "tool", nil, "a tool name (repeatable)")
}

func (f *overlayFlags) empty() bool {
	return len(f.paths)+len(f.cmds)+len(f.hosts)+len(f.tools) == 0
}

func guardDenyCmd() *cobra.Command {
	var dir, project string
	var f overlayFlags
	cmd := &cobra.Command{
		Use:   "deny",
		Short: "Add deny rules to the local overlay (tightens the token; takes effect immediately)",
		Long: "Add extra denials on top of the signed token — e.g. `legant guard deny --cmd terraform\n" +
			"--path ./prod`. The overlay can ONLY tighten (never widen past the token), takes effect\n" +
			"on the next tool call with no re-install, and applies to every installed agent.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.empty() {
				return fmt.Errorf("nothing to deny — pass --path/--cmd/--host/--tool")
			}
			p := ccguard.OverlayPath(resolveGuardDir(dir, project))
			ov, err := ccguard.LoadOverlay(p)
			if err != nil {
				return err
			}
			if ov == nil {
				ov = &ccguard.Overlay{}
			}
			ov.Add(f.paths, f.cmds, f.hosts, f.tools)
			if err := ccguard.SaveOverlay(p, ov); err != nil {
				return err
			}
			fmt.Printf("Updated overlay %s\n", p)
			printOverlay(ov)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "guard setup dir (default: the per-project dir)")
	cmd.Flags().StringVar(&project, "project", ".", "project root")
	f.bind(cmd)
	return cmd
}

func guardAllowCmd() *cobra.Command {
	var dir, project string
	var f overlayFlags
	cmd := &cobra.Command{
		Use:   "allow",
		Short: "Remove deny rules from the local overlay (un-does a local restriction)",
		Long: "Remove entries previously added with `guard deny`. This only edits the local overlay —\n" +
			"it can never grant something the signed token denies.",
		RunE: func(cmd *cobra.Command, args []string) error {
			p := ccguard.OverlayPath(resolveGuardDir(dir, project))
			ov, err := ccguard.LoadOverlay(p)
			if err != nil {
				return err
			}
			if ov == nil {
				fmt.Println("No overlay to edit.")
				return nil
			}
			ov.Remove(f.paths, f.cmds, f.hosts, f.tools)
			if err := ccguard.SaveOverlay(p, ov); err != nil {
				return err
			}
			fmt.Printf("Updated overlay %s\n", p)
			printOverlay(ov)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "guard setup dir (default: the per-project dir)")
	cmd.Flags().StringVar(&project, "project", ".", "project root")
	f.bind(cmd)
	return cmd
}

func guardRulesCmd() *cobra.Command {
	var dir, project string
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Show the local deny overlay (the extra restrictions on top of the token)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ov, err := ccguard.LoadOverlay(ccguard.OverlayPath(resolveGuardDir(dir, project)))
			if err != nil {
				return err
			}
			if ov == nil || ov.Empty() {
				fmt.Println("No overlay rules. (The token's own rule: legant guard show)")
				return nil
			}
			printOverlay(ov)
			fmt.Println("\nThe token's own rule:  legant guard show")
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "guard setup dir (default: the per-project dir)")
	cmd.Flags().StringVar(&project, "project", ".", "project root")
	return cmd
}

func printOverlay(ov *ccguard.Overlay) {
	if ov.Empty() {
		fmt.Println("  (overlay is now empty)")
		return
	}
	show := func(label string, vs []string) {
		for _, v := range vs {
			fmt.Printf("  − %-6s %s\n", label, v)
		}
	}
	show("path", ov.DenyPaths)
	show("cmd", ov.DenyCmds)
	show("host", ov.DenyHosts)
	show("tool", ov.DenyTools)
}

func guardInstallCmd() *cobra.Command {
	var dir, project, role, tool string
	var userScope bool
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install the guard hook into your coding agent(s): Claude Code, Codex, opencode",
		Long: "One command to make Legant govern your coding agent. It sets up a local guard\n" +
			"(key, role tokens, revocation feed) if needed, then wires a PreToolUse hook into\n" +
			"each detected agent so every tool call is authorized offline. Re-run to change the\n" +
			"--role; `legant guard uninstall` removes it.",
		RunE: func(cmd *cobra.Command, args []string) error {
			var tools []string
			switch tool {
			case "", "auto":
				tools = nil // auto-detect installed agents
			case "all":
				tools = []string{"claude-code", "codex", "opencode"}
			default:
				tools = []string{tool}
			}
			res, err := ccguard.Install(ccguard.InstallOptions{
				Dir: dir, Project: project, Role: role, Tools: tools, UserScope: userScope,
			})
			if err != nil {
				return err
			}
			r := role
			if r == "" {
				r = "open"
			}
			fmt.Printf("Installed the Legant guard (role %q) into:\n", r)
			for _, x := range res {
				fmt.Printf("  ✓ %-12s %s\n        %s\n", x.Tool, x.Path, x.Note)
			}
			fmt.Printf("\nStart a FRESH agent session in this project to load the hook, then try a denied\n")
			fmt.Printf("action (e.g. ask it to run `curl`): it's blocked even in bypass / --yolo / full-auto.\n")
			fmt.Printf("Inspect the rule:  legant guard show --role %s\n", r)
			fmt.Printf("Change the rule:   legant guard install --role reviewer|builder|open|operator\n")
			fmt.Printf("Remove it:         legant guard uninstall\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "guard setup dir (default: a per-project dir OUTSIDE the project)")
	cmd.Flags().StringVar(&project, "project", ".", "project root the agent works in")
	cmd.Flags().StringVar(&role, "role", "open", "rule set: reviewer | builder | open | operator")
	cmd.Flags().StringVar(&tool, "tool", "", "claude-code | codex | opencode | all (default: auto-detect installed)")
	cmd.Flags().BoolVar(&userScope, "user", false, "install at user/global scope where supported (codex, opencode)")
	return cmd
}

func guardUninstallCmd() *cobra.Command {
	var project string
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the Legant guard hook from all agents (project + user scope)",
		RunE: func(cmd *cobra.Command, args []string) error {
			res := ccguard.Uninstall(project)
			if len(res) == 0 {
				fmt.Println("No Legant guard hooks found to remove.")
				return nil
			}
			fmt.Println("Removed the Legant guard from:")
			for _, x := range res {
				fmt.Printf("  ✓ %s  (%s)\n", x.Path, x.Note)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&project, "project", ".", "project root")
	return cmd
}

func guardShowCmd() *cobra.Command {
	var dir, project, role, tokenFile string
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Decode and display the rule a delegation token carries (scope, allow/deny, validity)",
		RunE: func(cmd *cobra.Command, args []string) error {
			d := resolveGuardDir(dir, project)
			tf := tokenFile
			if tf == "" {
				tf = filepath.Join(d, role+".jwt")
			}
			out, err := ccguard.ShowFromDir(d, tf, time.Now())
			if err != nil {
				return err
			}
			fmt.Print(out)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "guard setup directory (default: the per-project dir)")
	cmd.Flags().StringVar(&project, "project", ".", "project root (locates the default guard dir)")
	cmd.Flags().StringVar(&role, "role", "open", "built-in role token to show: reviewer | builder | open | operator")
	cmd.Flags().StringVar(&tokenFile, "token-file", "", "show a specific token file instead of a role")
	return cmd
}

func guardCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:           "check",
		Short:         "PreToolUse hook entrypoint: read a tool-call event on stdin, allow or deny",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := ccguard.RunCheck(os.Stdin)
			if err != nil {
				// Cannot even read the event → NON-blocking error (exit 1, not 2): a
				// broken pipe must never brick a session.
				fmt.Fprintln(os.Stderr, "legant guard: "+err.Error())
				os.Exit(1)
			}
			if res.Block {
				// Exit code 2 is the HARD block: Claude Code stops the tool before
				// permission evaluation, so it bites even in bypassPermissions mode.
				// The stderr reason is fed back to the agent.
				fmt.Fprintln(os.Stderr, "Legant: "+res.Reason)
				os.Exit(2)
			}
			return nil // allow → no output, exit 0
		},
	}
}

func guardDemoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "demo",
		Short: "Run a self-contained, narrated guard scenario (no DB, no Claude Code needed)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return ccguard.RunDemo(os.Stdout)
		},
	}
}

func guardInitCmd() *cobra.Command {
	var dir, project string
	var ttl time.Duration
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write a local, offline guard setup (key, JWKS, role tokens, feed) + a settings.json hook",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := ccguard.InitLocal(dir, project, ttl, time.Now())
			if err != nil {
				return err
			}
			fmt.Printf("Wrote a local Legant guard setup to %s\n\n", s.Dir)
			fmt.Printf("  key.pem        local demo signing key (keep private)\n")
			fmt.Printf("  jwks.json      public keys the guard verifies against\n")
			fmt.Printf("  feed.jwt       signed revocation feed (empty)\n")
			for role, p := range s.Tokens {
				fmt.Printf("  %-14s token for role %q\n", filepathBase(p), role)
			}
			fmt.Printf("\nAdd this to your project's .claude/settings.json (active role: builder):\n\n%s\n\n", s.SettingsJSON)
			fmt.Printf("Switch roles by pointing LEGANT_GUARD_TOKEN_FILE at reviewer.jwt / operator.jwt.\n")
			fmt.Printf("Revoke the active token mid-session with:  legant guard revoke --dir %s --token-file <file>\n", s.Dir)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "guard setup directory (default: a per-project dir under your user config, OUTSIDE the project)")
	cmd.Flags().StringVar(&project, "project", ".", "project root the agent may read/write within")
	cmd.Flags().DurationVar(&ttl, "ttl", 8*time.Hour, "token lifetime")
	return cmd
}

// resolveGuardDir returns the explicit --dir if set, else the default per-project
// dir outside the project — keeping init/mint/revoke pointed at the same place.
func resolveGuardDir(dir, project string) string {
	if dir != "" {
		return dir
	}
	abs := project
	if a, err := filepath.Abs(project); err == nil {
		abs = a
	}
	return ccguard.DefaultGuardDir(abs)
}

func guardMintCmd() *cobra.Command {
	var dir, role, user, agent, project, parent, scopes string
	var ttl time.Duration
	cmd := &cobra.Command{
		Use:   "mint",
		Short: "Mint a token for a role, or an attenuated child token from --parent (prints the token)",
		Long: "Mint a delegation token for a built-in role using the local key.\n\n" +
			"With --parent, mint an ATTENUATED CHILD token for a sub-agent: the requested\n" +
			"--scopes must be a subset of the parent's, constraints are tightened, expiry is\n" +
			"clamped to the parent's, and the sub/act provenance chain is extended. Escalation\n" +
			"(asking for a scope the parent lacks) is refused.",
		RunE: func(cmd *cobra.Command, args []string) error {
			d := resolveGuardDir(dir, project)
			if parent != "" {
				tok, err := ccguard.MintChildToken(d, parent, agent, splitScopes(scopes), ttl, time.Now())
				if err != nil {
					return err
				}
				fmt.Println(tok)
				return nil
			}
			tok, err := ccguard.MintRoleToken(d, role, user, agent, project, ttl, time.Now())
			if err != nil {
				return err
			}
			fmt.Println(tok)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "guard setup directory (default: the per-project dir from init)")
	cmd.Flags().StringVar(&role, "role", "builder", "role: reviewer | builder | operator")
	cmd.Flags().StringVar(&user, "user", "user:local", "the delegating user principal")
	cmd.Flags().StringVar(&agent, "agent", "", "the agent principal (default agent:<role> / agent:subagent)")
	cmd.Flags().StringVar(&project, "project", ".", "project root for path-scoped roles")
	cmd.Flags().DurationVar(&ttl, "ttl", 8*time.Hour, "token lifetime")
	cmd.Flags().StringVar(&parent, "parent", "", "a parent token file to attenuate (mints a sub-agent child token)")
	cmd.Flags().StringVar(&scopes, "scopes", "", "comma/space-separated child scopes (a subset of the parent's)")
	return cmd
}

// splitScopes parses a comma/space-separated scope list.
func splitScopes(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func guardRevokeCmd() *cobra.Command {
	var dir, project, jti, tokenFile string
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Add a token id to the local signed revocation feed (kills it mid-session)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if jti == "" && tokenFile == "" {
				return fmt.Errorf("provide --jti or --token-file")
			}
			if jti == "" {
				b, err := os.ReadFile(tokenFile)
				if err != nil {
					return err
				}
				jti = ccguard.JTIOf(string(b))
				if jti == "" {
					return fmt.Errorf("could not read a jti from %s", tokenFile)
				}
			}
			ver, err := ccguard.RevokeJTI(resolveGuardDir(dir, project), jti, time.Now())
			if err != nil {
				return err
			}
			fmt.Printf("revoked %s — published feed version %d\n", jti, ver)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "guard setup directory (default: the per-project dir from init)")
	cmd.Flags().StringVar(&project, "project", ".", "project root (locates the default guard dir)")
	cmd.Flags().StringVar(&jti, "jti", "", "the token id to revoke")
	cmd.Flags().StringVar(&tokenFile, "token-file", "", "a token file to revoke (its jti is extracted)")
	return cmd
}

func filepathBase(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}
