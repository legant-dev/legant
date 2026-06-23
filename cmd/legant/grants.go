package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/legant-dev/legant/internal/ccguard"
	"github.com/legant-dev/legant/internal/delegation"
	"github.com/legant-dev/legant/internal/grants"
	"github.com/legant-dev/legant/sdk"
)

// These are the SEGMENT-NEUTRAL, top-level delegation verbs. They operate on a
// local, offline trust setup (a key + JWKS + signed feed under --dir, default
// .legant/), so they need no server or database — the same offline model the
// resource-server SDK verifies against. `legant guard` is the coding-agent skin on
// the same primitives; these are the general ones.

func initCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "init", Short: "Scaffold Legant config files (grants, resource-server, …)"}
	cmd.AddCommand(initGrantsCmd(), initResourceServerCmd())
	return cmd
}

func initGrantsCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "grants",
		Short: "Write a commented legant.grants.yaml starter",
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := os.Stat(out); err == nil {
				return fmt.Errorf("%s already exists — refusing to overwrite", out)
			}
			if err := os.WriteFile(out, []byte(grants.StarterYAML), 0o644); err != nil {
				return err
			}
			fmt.Printf("Wrote %s\n\nNext:\n  legant lint  -f %s\n  legant apply -f %s\n", out, out, out)
			return nil
		},
	}
	cmd.Flags().StringVarP(&out, "out", "o", "legant.grants.yaml", "output path")
	return cmd
}

func lintCmd() *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "lint",
		Short: "Validate a grants file (no side effects); non-zero exit on error",
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := grants.Parse(file)
			if err != nil {
				return err
			}
			issues := f.Lint()
			for _, i := range issues {
				fmt.Println(i.String())
			}
			if grants.HasErrors(issues) {
				return fmt.Errorf("lint failed: %d issue(s)", len(issues))
			}
			if len(issues) == 0 {
				fmt.Printf("ok: %s is valid (%d grant(s))\n", file, len(f.Grants))
			} else {
				fmt.Printf("ok with warnings: %s (%d grant(s))\n", file, len(f.Grants))
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "legant.grants.yaml", "grants file")
	return cmd
}

func applyCmd() *cobra.Command {
	var file, dir string
	var prune, force bool
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Reconcile a grants file into signed tokens (idempotent; shows a diff)",
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := grants.Parse(file)
			if err != nil {
				return err
			}
			if issues := f.Lint(); grants.HasErrors(issues) {
				for _, i := range issues {
					fmt.Println(i.String())
				}
				return fmt.Errorf("refusing to apply: lint failed (run `legant lint -f %s`)", file)
			}
			now := time.Now()
			s, err := grants.EnsureSetup(dir, f.Issuer, now)
			if err != nil {
				return err
			}
			if s.Created() {
				fmt.Printf("initialized offline setup in %s (key.pem, jwks.json, feed.jwt). Add it to .gitignore\n", s.Dir)
			}
			res, err := f.Apply(s, force, now)
			if err != nil {
				return err
			}
			mark := map[string]string{"create": "+", "update": "~", "unchanged": "="}
			for _, c := range res.Changes {
				fmt.Printf("  %s %-28s %-22s -> %s  (%s)\n", mark[c.Action], c.Name, c.Agent, c.Audience, filepath.Join(s.Dir, c.File))
			}
			if len(res.Orphans) > 0 {
				if prune {
					n, _ := s.Prune(res.Orphans, now)
					fmt.Printf("pruned %d orphaned token(s) and revoked %d on the feed\n", len(res.Orphans), n)
				} else {
					fmt.Printf("\n%d orphaned token file(s) not in %s (run with --prune to remove + revoke):\n", len(res.Orphans), file)
					for _, o := range res.Orphans {
						fmt.Printf("  ? %s\n", o)
					}
				}
			}
			fmt.Printf("\napplied: %d grant(s), %d token(s) minted\n", len(res.Changes), res.Minted)
			return nil
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "legant.grants.yaml", "grants file")
	cmd.Flags().StringVar(&dir, "dir", ".legant", "offline setup dir (key/JWKS/feed/tokens)")
	cmd.Flags().BoolVar(&prune, "prune", false, "remove + revoke token files no longer declared")
	cmd.Flags().BoolVar(&force, "force", false, "re-mint even unchanged grants (refresh TTL)")
	return cmd
}

func mintCmd() *cobra.Command {
	var dir, user, principal, agent, audience, scopes, start, end, tz string
	var categories, tools, resources []string
	var weekdays []int
	var maxAmount float64
	var ttl time.Duration
	var useKeystore bool
	cmd := &cobra.Command{
		Use:   "mint",
		Short: "Mint one ad-hoc delegation token from flags (prints the token)",
		Long: "Mint a single delegation token. By default it signs with the OFFLINE local\n" +
			"key under --dir. With --keystore it signs with the running deployment's server\n" +
			"key (from config + the DB keystore), so a live gateway/resource server accepts\n" +
			"it. For repeatable, reviewable authority prefer a grants file + `legant apply`.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if user == "" {
				user = principal // --principal is an alias for --user (matches the grants.yaml key)
			}
			if user == "" || agent == "" {
				return fmt.Errorf("--user (or --principal) and --agent are required")
			}
			sc := splitScopes(scopes)
			if len(sc) == 0 {
				return fmt.Errorf("--scopes is required (comma/space separated)")
			}
			if audience == "" {
				return fmt.Errorf("--audience is required (the resource server this token is for)")
			}
			cnst, err := constraintsFromFlags(cmd, maxAmount, categories, tools, resources, weekdays, start, end, tz)
			if err != nil {
				return err
			}
			now := time.Now()
			if useKeystore {
				tok, err := mintWithKeystore(user, agent, sc, audience, &cnst, ttl, now)
				if err != nil {
					return err
				}
				fmt.Println(tok)
				return nil
			}
			s, err := grants.EnsureSetup(dir, "", now)
			if err != nil {
				return err
			}
			g := delegation.NewRootGrant(user, agent, sc, cnst, ttl, now)
			tok, _, err := ccguard.MintGrant(s.Signer, g, audience, now)
			if err != nil {
				return err
			}
			fmt.Println(tok)
			return nil
		},
	}
	cmd.Flags().BoolVar(&useKeystore, "keystore", false, "sign with the server's DB keystore key (for a live deployment) instead of the local key")
	cmd.Flags().StringVar(&dir, "dir", ".legant", "offline setup dir (key/JWKS/feed)")
	cmd.Flags().StringVar(&user, "user", "", "the delegating principal (e.g. user:alice)")
	cmd.Flags().StringVar(&principal, "principal", "", "alias for --user (matches the grants.yaml `principal:` key)")
	cmd.Flags().StringVar(&agent, "agent", "", "the agent principal (e.g. agent:copilot)")
	cmd.Flags().StringVar(&audience, "audience", "", "the resource-server audience (RFC 8707)")
	cmd.Flags().StringVar(&scopes, "scopes", "", "comma/space-separated capability scopes")
	cmd.Flags().Float64Var(&maxAmount, "max-amount", 0, "cap the action amount (0 = no cap)")
	cmd.Flags().StringArrayVar(&categories, "category", nil, "allowed category (repeatable)")
	cmd.Flags().StringArrayVar(&tools, "tool", nil, "allowed tool (repeatable)")
	cmd.Flags().StringArrayVar(&resources, "resource", nil, "allowed resource audience (repeatable)")
	cmd.Flags().IntSliceVar(&weekdays, "weekdays", nil, "allowed weekdays 0=Sun..6=Sat (time window)")
	cmd.Flags().StringVar(&start, "start", "", "time-window start HH:MM")
	cmd.Flags().StringVar(&end, "end", "", "time-window end HH:MM")
	cmd.Flags().StringVar(&tz, "tz", "", "time-window IANA timezone (default UTC)")
	cmd.Flags().DurationVar(&ttl, "ttl", time.Hour, "token lifetime")
	return cmd
}

func constraintsFromFlags(cmd *cobra.Command, maxAmount float64, categories, tools, resources []string, weekdays []int, start, end, tz string) (delegation.Constraints, error) {
	c := delegation.Constraints{Categories: categories, Tools: tools, Resources: resources}
	if cmd.Flags().Changed("max-amount") {
		v := maxAmount
		if v < 0 {
			return c, fmt.Errorf("--max-amount must be >= 0")
		}
		c.MaxAmount = &v
	}
	if start != "" || end != "" || len(weekdays) > 0 || tz != "" {
		sm, err := hhmm(start)
		if err != nil {
			return c, fmt.Errorf("--start: %w", err)
		}
		em, err := hhmm(end)
		if err != nil {
			return c, fmt.Errorf("--end: %w", err)
		}
		tw := &delegation.TimeWindow{Weekdays: weekdays, StartMin: sm, EndMin: em, TZ: tz}
		if err := tw.Validate(); err != nil {
			return c, err
		}
		c.TimeWindow = tw
	}
	return c, nil
}

func hhmm(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("required with a time window (HH:MM)")
	}
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0, fmt.Errorf("%q is not HH:MM", s)
	}
	return t.Hour()*60 + t.Minute(), nil
}

func showCmd() *cobra.Command {
	var dir, tokenFile string
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Decode and display the rule a delegation token carries",
		RunE: func(cmd *cobra.Command, args []string) error {
			if tokenFile == "" {
				return fmt.Errorf("--token-file is required")
			}
			out, err := ccguard.ShowFromDir(dir, tokenFile, time.Now())
			if err != nil {
				return err
			}
			fmt.Print(out)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", ".legant", "offline setup dir (for JWKS + feed to check validity/revocation)")
	cmd.Flags().StringVar(&tokenFile, "token-file", "", "the token file to decode")
	return cmd
}

func revokeCmd() *cobra.Command {
	var dir, jti, tokenFile string
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Add a token id to the local signed revocation feed (kills it offline)",
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
			ver, err := ccguard.RevokeJTI(dir, jti, time.Now())
			if err != nil {
				return err
			}
			fmt.Printf("revoked %s, published feed version %d\n", jti, ver)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", ".legant", "offline setup dir (holds the signed feed)")
	cmd.Flags().StringVar(&jti, "jti", "", "the token id to revoke")
	cmd.Flags().StringVar(&tokenFile, "token-file", "", "a token file to revoke (its jti is extracted)")
	return cmd
}

func whoCanCmd() *cobra.Command {
	var file, dir, scope, resource, tool, category string
	var amount float64
	cmd := &cobra.Command{
		Use:   "who-can",
		Short: "Show which declared grants would permit an action (offline authorize)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if scope == "" {
				return fmt.Errorf("--scope is required (the capability the action needs)")
			}
			f, err := grants.Parse(file)
			if err != nil {
				return err
			}
			now := time.Now()
			s, err := grants.EnsureSetup(dir, f.Issuer, now)
			if err != nil {
				return err
			}
			action := sdk.Action{Scope: scope, Resource: resource, Tool: tool, Category: category, Amount: amount}
			matches, err := f.WhoCan(s, action, now)
			if err != nil {
				return err
			}
			if len(matches) == 0 {
				fmt.Printf("no declared grant permits scope=%q resource=%q tool=%q\n", scope, resource, tool)
				return nil
			}
			fmt.Printf("grants that permit scope=%q resource=%q tool=%q amount=%g:\n", scope, resource, tool, amount)
			for _, m := range matches {
				note := ""
				if m.TimeBoxed {
					note = "  (only inside its time window — closed right now)"
				}
				fmt.Printf("  ✓ %-28s %s  (aud %s)%s\n", m.Name, m.Provenance, m.Audience, note)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "legant.grants.yaml", "grants file")
	cmd.Flags().StringVar(&dir, "dir", ".legant", "offline setup dir")
	cmd.Flags().StringVar(&scope, "scope", "", "the scope the action requires")
	cmd.Flags().StringVar(&resource, "resource", "", "the resource audience the action targets")
	cmd.Flags().StringVar(&tool, "tool", "", "the tool the action invokes")
	cmd.Flags().StringVar(&category, "category", "", "the category the action targets")
	cmd.Flags().Float64Var(&amount, "amount", 0, "the action amount")
	return cmd
}
