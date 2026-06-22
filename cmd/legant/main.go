package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	legant "github.com/legant-dev/legant"
	"github.com/legant-dev/legant/internal/audit"
	"github.com/legant-dev/legant/internal/auth"
	"github.com/legant-dev/legant/internal/config"
	"github.com/legant-dev/legant/internal/db"
	"github.com/legant-dev/legant/internal/keystore"
	"github.com/legant-dev/legant/internal/live"
	"github.com/legant-dev/legant/internal/mcpgw"
	"github.com/legant-dev/legant/internal/metrics"
	"github.com/legant-dev/legant/internal/middleware"
	"github.com/legant-dev/legant/internal/retention"
	"github.com/legant-dev/legant/internal/revocation"
	"github.com/legant-dev/legant/internal/safehttp"
	"github.com/legant-dev/legant/internal/server"
)

var version = "dev"

func main() {
	root := &cobra.Command{
		Use:     "legant",
		Short:   "Legant - Open Source Delegated Authorization for AI Agents",
		Version: version,
		// A runtime error from a command (e.g. a broken audit chain) should print
		// just the error, not the full usage text — keeps CronJob/CI logs clean.
		SilenceUsage: true,
	}
	metrics.SetBuildInfo(version)

	root.AddCommand(serveCmd())
	root.AddCommand(migrateCmd())
	root.AddCommand(keysCmd())
	root.AddCommand(adminCmd())
	root.AddCommand(dcrCmd())
	root.AddCommand(gatewayCmd())
	root.AddCommand(maintenanceCmd())
	root.AddCommand(auditCmd())
	root.AddCommand(guardCmd())
	// Segment-neutral delegation verbs (offline, no DB) — see grants.go.
	root.AddCommand(initCmd())
	root.AddCommand(lintCmd())
	root.AddCommand(applyCmd())
	root.AddCommand(mintCmd())
	root.AddCommand(showCmd())
	root.AddCommand(revokeCmd())
	root.AddCommand(whoCanCmd())
	root.AddCommand(snippetCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func serveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the Legant server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe()
		},
	}
}

func migrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Run database migrations",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "up",
		Short: "Run pending migrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadMinimal()
			if err != nil {
				return err
			}
			migFS, err := fs.Sub(legant.MigrationsFS, "migrations")
			if err != nil {
				return err
			}
			return db.RunMigrations(migFS, cfg.Database.URL)
		},
	})

	down := &cobra.Command{
		Use:   "down",
		Short: "Roll back ALL migrations (destructive; requires --all)",
		RunE: func(cmd *cobra.Command, args []string) error {
			all, _ := cmd.Flags().GetBool("all")
			if !all {
				return fmt.Errorf("refusing to roll back without --all (this drops all schema and data)")
			}
			cfg, err := config.LoadMinimal()
			if err != nil {
				return err
			}
			migFS, err := fs.Sub(legant.MigrationsFS, "migrations")
			if err != nil {
				return err
			}
			return db.MigrateDownAll(migFS, cfg.Database.URL)
		},
	}
	down.Flags().Bool("all", false, "confirm rolling back every migration")
	cmd.AddCommand(down)

	cmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the current migration version and dirty flag",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadMinimal()
			if err != nil {
				return err
			}
			migFS, err := fs.Sub(legant.MigrationsFS, "migrations")
			if err != nil {
				return err
			}
			v, dirty, err := db.MigrationStatus(migFS, cfg.Database.URL)
			if err != nil {
				return err
			}
			fmt.Printf("version=%d dirty=%v\n", v, dirty)
			return nil
		},
	})

	return cmd
}

// keysCmd manages signing keys: listing, rotation, pruning retired keys, and
// re-encrypting under a new key-encryption secret.
func keysCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "keys", Short: "Manage signing keys"}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List signing keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			ks, pool, _, err := openKeystore(ctx)
			if err != nil {
				return err
			}
			defer pool.Close()
			keys, err := ks.List(ctx)
			if err != nil {
				return err
			}
			active := ks.ActiveKID()
			fmt.Printf("%-16s %-8s %-30s %s\n", "KID", "ROLE", "CREATED", "RETIRES")
			for _, k := range keys {
				role := "verify"
				if k.ID == active {
					role = "ACTIVE"
				}
				retires := "-"
				if k.ExpiresAt != nil {
					retires = k.ExpiresAt.Format("2006-01-02 15:04")
				}
				fmt.Printf("%-16s %-8s %-30s %s\n", k.ID, role, k.CreatedAt.Format("2006-01-02 15:04:05"), retires)
			}
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "rotate",
		Short: "Generate a new active signing key (old key stays published during the overlap window)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			ks, pool, _, err := openKeystore(ctx)
			if err != nil {
				return err
			}
			defer pool.Close()
			kid, err := ks.Rotate(ctx)
			if err != nil {
				return err
			}
			fmt.Printf("rotated: new active signing key %s\n", kid)
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "prune",
		Short: "Deactivate retired keys whose overlap window has passed",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			ks, pool, _, err := openKeystore(ctx)
			if err != nil {
				return err
			}
			defer pool.Close()
			n, err := ks.Prune(ctx)
			if err != nil {
				return err
			}
			fmt.Printf("pruned %d retired key(s)\n", n)
			return nil
		},
	})

	reencrypt := &cobra.Command{
		Use:   "reencrypt",
		Short: "Re-wrap all signing keys under a new key-encryption secret",
		RunE: func(cmd *cobra.Command, args []string) error {
			newSecret, _ := cmd.Flags().GetString("new-secret")
			if len(newSecret) < 32 {
				return fmt.Errorf("--new-secret must be at least 32 bytes")
			}
			ctx := context.Background()
			ks, pool, _, err := openKeystore(ctx)
			if err != nil {
				return err
			}
			defer pool.Close()
			if err := ks.Reencrypt(ctx, []byte(newSecret)); err != nil {
				return err
			}
			fmt.Println("re-encrypted all signing keys under the new secret; update LEGANT_SECRETS_KEY_ENCRYPTION before next start")
			return nil
		},
	}
	reencrypt.Flags().String("new-secret", "", "the new key-encryption secret (32+ bytes)")
	cmd.AddCommand(reencrypt)

	return cmd
}

// auditCmd verifies the tamper-evident audit hash chain.
func auditCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "audit", Short: "Audit-log integrity operations"}

	verify := &cobra.Command{
		Use:   "verify",
		Short: "Verify the audit hash chain (and pin a new anchor) ; report the first tamper, if any",
		RunE: func(cmd *cobra.Command, args []string) error {
			noAnchor, _ := cmd.Flags().GetBool("no-anchor")
			ctx := context.Background()
			cfg, err := config.LoadMinimal()
			if err != nil {
				return err
			}
			pool, err := db.NewPool(ctx, cfg.Database)
			if err != nil {
				return err
			}
			defer pool.Close()

			res, err := audit.Verify(ctx, pool)
			if err != nil {
				return err
			}
			if !res.OK {
				// Non-zero exit so a scheduled check / CI alerts on tampering.
				return fmt.Errorf("audit chain BROKEN (%s) at event id=%d; %d events scanned",
					res.BreakKind, res.BreakID, res.Events)
			}
			// Pin the verified head so a future run can detect tail truncation.
			if !noAnchor {
				if err := audit.Anchor(ctx, pool); err != nil {
					return fmt.Errorf("verified OK but could not write anchor: %w", err)
				}
			}
			fmt.Printf("audit chain OK: %d events, head=%s\n", res.Events, res.HeadHash)
			return nil
		},
	}
	verify.Flags().Bool("no-anchor", false, "verify without recording a new anchor checkpoint")
	cmd.AddCommand(verify)

	anchor := &cobra.Command{
		Use:   "anchor",
		Short: "Sign a tamper-evident anchor of the audit chain (ship it off-box), or --check the live chain against one",
		Long: "Without --check: verifies the chain, signs a checkpoint with the active key, stores it, and " +
			"optionally exports the signed JSON to a file (--out) and/or a webhook (--webhook); ship that to an " +
			"append-only/off-box store. With --check FILE: validates the live chain against a trusted off-box anchor, " +
			"detecting truncation or a rewritten prefix even if the database's own anchor table was forged.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			check, _ := cmd.Flags().GetString("check")
			out, _ := cmd.Flags().GetString("out")
			webhook, _ := cmd.Flags().GetString("webhook")
			ctx := context.Background()
			ks, pool, _, err := openKeystore(ctx)
			if err != nil {
				return err
			}
			defer pool.Close()

			if check != "" {
				b, err := os.ReadFile(check)
				if err != nil {
					return err
				}
				var rec audit.AnchorRecord
				if err := json.Unmarshal(b, &rec); err != nil {
					return fmt.Errorf("parse anchor %s: %w", check, err)
				}
				res, err := audit.CheckAgainstAnchor(ctx, pool, rec, ks.VerifierKeys())
				if err != nil {
					return err
				}
				if !res.OK {
					return fmt.Errorf("audit chain does NOT match the trusted anchor (%s): %d events now, anchor pinned %d",
						res.BreakKind, res.Events, rec.Count)
				}
				fmt.Printf("audit chain matches the trusted anchor: %d events, head=%s\n", res.Events, res.HeadHash)
				return nil
			}

			rec, err := audit.AnchorSigned(ctx, pool, ks)
			if err != nil {
				return err
			}
			blob, _ := json.Marshal(rec)
			if out != "" {
				f, err := os.OpenFile(out, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
				if err != nil {
					return err
				}
				defer f.Close()
				if _, err := f.Write(append(blob, '\n')); err != nil {
					return err
				}
			}
			if webhook != "" {
				resp, err := http.Post(webhook, "application/json", bytes.NewReader(blob))
				if err != nil {
					return fmt.Errorf("anchor webhook: %w", err)
				}
				resp.Body.Close()
				if resp.StatusCode >= 300 {
					return fmt.Errorf("anchor webhook returned %d", resp.StatusCode)
				}
			}
			fmt.Printf("signed anchor: count=%d head=%s kid=%s\n%s\n", rec.Count, rec.HeadHash, rec.KID, blob)
			return nil
		},
	}
	anchor.Flags().String("check", "", "verify the live chain against a trusted off-box anchor JSON file instead of creating one")
	anchor.Flags().String("out", "", "append the signed anchor JSON to this file (ship it to an append-only/off-box store)")
	anchor.Flags().String("webhook", "", "POST the signed anchor JSON to this URL")
	cmd.AddCommand(anchor)
	return cmd
}

// maintenanceCmd holds operational housekeeping run on a schedule (e.g. a
// Kubernetes CronJob): pruning expired/dead operational rows.
func maintenanceCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "maintenance", Short: "Operational housekeeping"}

	prune := &cobra.Command{
		Use:   "prune",
		Short: "Delete expired sessions/tokens, dead delegation tokens, and aged audit events",
		RunE: func(cmd *cobra.Command, args []string) error {
			tokenGrace, _ := cmd.Flags().GetDuration("token-grace")
			auditRetention, _ := cmd.Flags().GetDuration("audit-retention")
			dryRun, _ := cmd.Flags().GetBool("dry-run")

			ctx := context.Background()
			// Retention only touches the database — no secrets required.
			cfg, err := config.LoadMinimal()
			if err != nil {
				return err
			}
			pool, err := db.NewPool(ctx, cfg.Database)
			if err != nil {
				return err
			}
			defer pool.Close()

			policy := retention.Policy{TokenGrace: tokenGrace, AuditRetention: auditRetention}
			res, err := retention.Prune(ctx, pool, policy, dryRun)
			if err != nil {
				return err
			}
			verb := "pruned"
			if dryRun {
				verb = "would prune"
			}
			fmt.Printf("%s: sessions=%d email_tokens=%d dcr_tokens=%d invitations=%d exchanged_tokens=%d oauth_tokens=%d agent_tokens=%d api_keys=%d audit_events=%d (total=%d)\n",
				verb, res.ExpiredSessions, res.StaleEmailTokens, res.ExhaustedDCRTokens,
				res.StaleInvitations, res.DeadExchangedTokens, res.ExpiredOAuthTokens,
				res.ExpiredAgentTokens, res.ExpiredAPIKeys, res.AgedAuditEvents, res.Total())
			return nil
		},
	}
	prune.Flags().Duration("token-grace", retention.DefaultPolicy.TokenGrace,
		"keep dead delegation tokens this long past expiry before purging")
	prune.Flags().Duration("audit-retention", 0,
		"delete audit events older than this (0 = keep forever)")
	prune.Flags().Bool("dry-run", false, "report what would be deleted without deleting")
	cmd.AddCommand(prune)

	return cmd
}

// adminCmd holds privileged bootstrap operations run offline with direct DB access.
func adminCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "admin", Short: "Administrative bootstrap commands"}

	cmd.AddCommand(&cobra.Command{
		Use:   "grant-superadmin <email>",
		Short: "Grant platform superadmin to a user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			pool, err := db.NewPool(ctx, cfg.Database)
			if err != nil {
				return err
			}
			defer pool.Close()

			email := args[0]
			tag, err := pool.Exec(ctx,
				`UPDATE users SET is_superadmin = true WHERE email = $1 AND status = 'active'`, email)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return fmt.Errorf("no active user with email %q", email)
			}
			// Critical, durable audit of a privileged grant.
			_, _ = pool.Exec(ctx,
				`INSERT INTO audit_events (actor_type, action, resource_type, resource_id, metadata)
				 VALUES ('system', 'admin.grant_superadmin', 'user', $1, '{"via":"cli"}')`, email)
			fmt.Printf("granted superadmin to %s\n", email)
			return nil
		},
	})

	return cmd
}

// gatewayCmd runs the MCP auth-gateway: a reverse proxy that enforces per-tool
// delegation in front of configured MCP upstreams.
func gatewayCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "gateway",
		Short: "Run the MCP auth-gateway (per-tool delegation enforcement in front of MCP servers)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			// Gateway mode does not run OAuth/session endpoints, so it does not
			// require the Fosite system or cookie secrets — only DB access and the
			// key-decryption material.
			cfg, err := config.LoadGateway()
			if err != nil {
				return err
			}
			pool, err := db.NewPool(ctx, cfg.Database)
			if err != nil {
				return err
			}
			defer pool.Close()

			encKey, err := cfg.Secrets.KeyEncryptionMaterial()
			if err != nil {
				return err
			}
			ks, err := keystore.Open(ctx, pool, encKey, cfg.Keystore.RotationOverlap)
			if err != nil {
				return err
			}
			go reloadKeystoreLoop(ctx, ks)

			ups := make([]*mcpgw.Upstream, 0, len(cfg.Gateway.Upstreams))
			for _, u := range cfg.Gateway.Upstreams {
				ups = append(ups, &mcpgw.Upstream{
					Slug: u.Slug, InboundAudience: u.InboundAudience, URL: u.URL,
					ResourceID: u.ResourceID, ToolScopes: u.ToolScopes,
				})
			}
			// The gateway publishes per-call decisions to the live console over
			// Postgres NOTIFY; the server's /admin/live consumes them.
			gwPub := live.NewPublisher(ctx, pool)
			gw, err := mcpgw.NewGateway(cfg.Issuer.URL, ks, revocation.NewStore(pool, gwPub), pool, gwPub, ups,
				mcpgw.WithDownstreamTTL(cfg.Gateway.DownstreamTTL),
				mcpgw.WithRevocationRefresh(cfg.Gateway.RevocationRefresh))
			if err != nil {
				return err
			}
			// In feed mode, load the revoked set before serving (fails closed if the
			// DB is unreachable at startup).
			if err := gw.StartRevocationRefresh(ctx); err != nil {
				return err
			}
			// Merge the DB-backed upstream registry (additive to static config) and
			// refresh it periodically so upstreams can be added without a redeploy.
			if err := gw.StartUpstreamRefresh(ctx, mcpgw.NewUpstreamStore(pool), 30*time.Second); err != nil {
				return err
			}

			r := chi.NewRouter()
			r.Use(middleware.RequestID)
			r.Use(metrics.Middleware)
			r.Use(middleware.Logging)
			r.Use(chimw.Recoverer)
			r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
			// Readiness: the gateway fails closed on a DB error (revocation check)
			// and needs an active signing key to mint downstream tokens, so a probe
			// must verify both before the pod receives traffic.
			r.Get("/readyz", func(w http.ResponseWriter, req *http.Request) {
				if err := pool.Ping(req.Context()); err != nil {
					slog.Warn("gateway readiness failed", "reason", "database unreachable")
					http.Error(w, "not ready", http.StatusServiceUnavailable)
					return
				}
				if ks.ActiveKID() == "" {
					slog.Warn("gateway readiness failed", "reason", "no active signing key")
					http.Error(w, "not ready", http.StatusServiceUnavailable)
					return
				}
				fmt.Fprint(w, "ok")
			})
			r.Handle("/metrics", metrics.Handler())
			r.Mount("/mcp", gw.Routes())

			httpSrv := &http.Server{Addr: cfg.Server.Addr(), Handler: r, ReadHeaderTimeout: 10 * time.Second}
			go func() {
				slog.Info("legant gateway starting", "addr", httpSrv.Addr, "upstreams", len(ups))
				if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					slog.Error("gateway server error", "error", err)
				}
			}()
			<-ctx.Done()
			shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return httpSrv.Shutdown(shutCtx)
		},
	}
}

// dcrCmd manages dynamic client registration (issuing initial access tokens).
func dcrCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "dcr", Short: "Dynamic client registration"}

	issue := &cobra.Command{
		Use:   "issue-token",
		Short: "Mint an initial access token that gates client registration",
		RunE: func(cmd *cobra.Command, args []string) error {
			maxUses, _ := cmd.Flags().GetInt("max-uses")
			ttlHours, _ := cmd.Flags().GetInt("ttl-hours")
			ctx := context.Background()
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			pool, err := db.NewPool(ctx, cfg.Database)
			if err != nil {
				return err
			}
			defer pool.Close()
			tok, err := auth.MintRegistrationToken(ctx, pool, maxUses, time.Duration(ttlHours)*time.Hour)
			if err != nil {
				return err
			}
			fmt.Println(tok)
			return nil
		},
	}
	issue.Flags().Int("max-uses", 1, "how many clients may register with this token")
	issue.Flags().Int("ttl-hours", 24, "token lifetime in hours (0 = never expires)")
	cmd.AddCommand(issue)
	return cmd
}

// reloadKeystoreLoop refreshes the in-memory signing keys on SIGHUP or
// periodically, so a `legant keys rotate` in another process is picked up by a
// running server without a restart.
func reloadKeystoreLoop(ctx context.Context, ks *keystore.Keystore) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-hup:
		}
		if err := ks.Reload(ctx); err != nil {
			slog.Error("keystore reload failed", "error", err)
			continue
		}
		auth.SetSigningKID(ks.ActiveKID())
		slog.Info("keystore reloaded", "active_kid", ks.ActiveKID())
	}
}

// openKeystore loads config, connects to the database, and opens the keystore.
// The caller owns the returned pool and must Close it.
func openKeystore(ctx context.Context) (*keystore.Keystore, *pgxpool.Pool, *config.Config, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, nil, err
	}
	pool, err := db.NewPool(ctx, cfg.Database)
	if err != nil {
		return nil, nil, nil, err
	}
	encKey, err := cfg.Secrets.KeyEncryptionMaterial()
	if err != nil {
		pool.Close()
		return nil, nil, nil, err
	}
	ks, err := keystore.Open(ctx, pool, encKey, cfg.Keystore.RotationOverlap)
	if err != nil {
		pool.Close()
		return nil, nil, nil, err
	}
	return ks, pool, cfg, nil
}

func runServe() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	slog.Info("starting legant",
		"version", version,
		"issuer", cfg.Issuer.URL,
		"addr", cfg.Server.Addr(),
	)

	// Cancelled on SIGINT/SIGTERM so background loops (e.g. keystore reload) exit
	// cleanly during shutdown rather than leaking.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Run migrations only when explicitly enabled (production runs them as a
	// separate pre-deploy step).
	if cfg.Database.AutoMigrate {
		migFS, err := fs.Sub(legant.MigrationsFS, "migrations")
		if err != nil {
			return fmt.Errorf("loading migrations: %w", err)
		}
		if err := db.RunMigrations(migFS, cfg.Database.URL); err != nil {
			return fmt.Errorf("running migrations: %w", err)
		}
	}

	// Connect to database
	pool, err := db.NewPool(ctx, cfg.Database)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}

	// Open the keystore: load (or bootstrap) the persistent signing key set.
	encKey, err := cfg.Secrets.KeyEncryptionMaterial()
	if err != nil {
		return fmt.Errorf("deriving key-encryption material: %w", err)
	}
	if cfg.Secrets.KeyEncryption == "" {
		slog.Warn("LEGANT_SECRETS_KEY_ENCRYPTION is not set; deriving the signing-key encryption key from LEGANT_SECRETS_SYSTEM. " +
			"Set a distinct value in production so a single leaked secret does not compromise both the Fosite HMAC and every signing key.")
	}
	ks, err := keystore.Open(ctx, pool, encKey, cfg.Keystore.RotationOverlap)
	if err != nil {
		return fmt.Errorf("opening keystore: %w", err)
	}
	auth.SetSigningKID(ks.ActiveKID())
	slog.Info("keystore opened", "active_kid", ks.ActiveKID(), "keys", len(ks.VerifierKeys()))
	go reloadKeystoreLoop(ctx, ks)

	// Create fosite storage and provider; enable CIMD (https-URL client ids)
	// resolution over an SSRF-hardened HTTP client.
	storage := auth.NewStorage(pool)
	storage.SetCIMDResolver(auth.NewCIMDResolver(safehttp.Client(false)))
	provider := auth.NewOAuth2Provider(storage, cfg.Issuer.URL, ks.ActiveSigner, []byte(cfg.Secrets.System))

	// Parse templates
	tmplFS, err := fs.Sub(legant.TemplatesFS, "web/templates")
	if err != nil {
		return fmt.Errorf("loading templates: %w", err)
	}
	templates, err := template.ParseFS(tmplFS, "*.html")
	if err != nil {
		return fmt.Errorf("parsing templates: %w", err)
	}

	// Create and start server
	srv := server.New(server.Deps{
		Config:    cfg,
		Pool:      pool,
		Provider:  provider,
		Keystore:  ks,
		Templates: templates,
	})

	return srv.Start()
}
