package server

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ory/fosite"

	"github.com/legant-dev/legant/internal/agent"
	"github.com/legant-dev/legant/internal/apikey"
	"github.com/legant-dev/legant/internal/audit"
	"github.com/legant-dev/legant/internal/auth"
	"github.com/legant-dev/legant/internal/authz"
	"github.com/legant-dev/legant/internal/client"
	"github.com/legant-dev/legant/internal/config"
	"github.com/legant-dev/legant/internal/delegation"
	"github.com/legant-dev/legant/internal/delegation/chains"
	"github.com/legant-dev/legant/internal/email"
	"github.com/legant-dev/legant/internal/keystore"
	"github.com/legant-dev/legant/internal/live"
	"github.com/legant-dev/legant/internal/mcpgw"
	"github.com/legant-dev/legant/internal/metrics"
	"github.com/legant-dev/legant/internal/middleware"
	"github.com/legant-dev/legant/internal/org"
	"github.com/legant-dev/legant/internal/revocation"
	"github.com/legant-dev/legant/internal/scim"
	"github.com/legant-dev/legant/internal/user"
)

type Server struct {
	cfg        *config.Config
	pool       *pgxpool.Pool
	router     chi.Router
	httpServer *http.Server
	hub        *live.Hub // real-time console fan-out, fed by the Postgres LISTEN loop
	bg         context.Context
	bgCancel   context.CancelFunc // cancels the live publisher + listener on shutdown
}

type Deps struct {
	Config    *config.Config
	Pool      *pgxpool.Pool
	Provider  fosite.OAuth2Provider
	Keystore  *keystore.Keystore
	Templates *template.Template
}

func New(deps Deps) *Server {
	r := chi.NewRouter()

	// Global middleware
	r.Use(middleware.RequestID)
	// Metrics middleware sits outside Logging/Recoverer so it records latency and
	// the final status code even for panics the Recoverer turns into a 500.
	r.Use(metrics.Middleware)
	// NOTE: chimw.RealIP is intentionally NOT used — it rewrites RemoteAddr from
	// the client-controlled X-Forwarded-For with no trusted-proxy allowlist, which
	// would let a caller spoof the source IP the rate limiter keys on. Restore it
	// only behind a configured trusted-proxy CIDR set.
	r.Use(middleware.Logging)
	r.Use(chimw.Recoverer)

	s := &Server{
		cfg:    deps.Config,
		pool:   deps.Pool,
		router: r,
	}
	// Background context for process-lifetime workers (live publisher + listener),
	// cancelled on shutdown before the pool closes.
	s.bg, s.bgCancel = context.WithCancel(context.Background())

	s.registerRoutes(deps)

	s.httpServer = &http.Server{
		Addr:         deps.Config.Server.Addr(),
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
}

func (s *Server) registerRoutes(deps Deps) {
	r := s.router

	// Secure cookies whenever the issuer is served over HTTPS.
	secureCookies := strings.HasPrefix(deps.Config.Issuer.URL, "https://")
	sessionManager := auth.NewSessionManager(
		deps.Pool,
		deps.Config.Secrets.Cookie,
		deps.Config.Session.Lifetime,
		secureCookies,
	)

	// Live console: one hub fanned out to SSE clients, fed by a Postgres LISTEN
	// loop (started in Start); one publisher (Postgres NOTIFY) shared by every
	// server-side emit site so mints and revokes appear in real time. Both the
	// gateway process and other replicas publish to the same channel.
	s.hub = live.NewHub(300)
	livePub := live.NewPublisher(s.bg, deps.Pool)

	authHandler := auth.NewHandler(deps.Provider, sessionManager)
	consentHandler := auth.NewConsentHandler(deps.Pool, sessionManager, deps.Templates)
	chainsService := chains.NewService(deps.Pool, livePub)
	accountHandler := auth.NewAccountHandler(chainsService, sessionManager, deps.Templates)
	adminHandler := auth.NewAdminHandler(deps.Pool, sessionManager, deps.Templates)
	liveHandler := auth.NewLiveHandler(deps.Pool, sessionManager, deps.Templates, s.hub, livePub, deps.Config.Server.LiveIngestToken)
	userHandler := user.NewHandler(user.NewService(deps.Pool))
	clientService := client.NewService(deps.Pool)
	clientHandler := client.NewHandler(clientService)
	registrar := auth.NewRegistrar(deps.Pool, clientService)
	orgService := org.NewService(deps.Pool)
	orgHandler := org.NewHandler(orgService)
	agentService := agent.NewService(deps.Pool)
	revocationStore := revocation.NewStore(deps.Pool, livePub)
	agentHandler := agent.NewHandler(agentService, revocationStore)
	apikeyHandler := apikey.NewHandler(apikey.NewService(deps.Pool))
	scimHandler := scim.NewHandler(deps.Pool)
	emailService := email.NewService(deps.Pool, deps.Config.Issuer.URL)

	// Authenticator resolves a request to a Principal via, in order: session
	// cookie, opaque agent token, or OAuth2 access token (introspection).
	authenticator := authz.NewAuthenticator(
		deps.Pool,
		func(r *http.Request) (string, bool) {
			sess, err := sessionManager.Get(r.Context(), r)
			if err != nil || sess.UserID == "" {
				return "", false
			}
			return sess.UserID, true
		},
		func(ctx context.Context, token string) (string, []string, string, bool) {
			ag, tok, err := agentService.ValidateToken(ctx, token)
			if err != nil {
				return "", nil, "", false
			}
			return ag.ID, tok.Scopes, tok.ID, true
		},
		func(ctx context.Context, token string) (string, []string, bool) {
			oas := auth.NewSession("")
			_, ar, err := deps.Provider.IntrospectToken(ctx, token, fosite.AccessToken, oas)
			if err != nil {
				return "", nil, false
			}
			return ar.GetSession().GetSubject(), ar.GetGrantedScopes(), true
		},
	)

	// RFC 8693 token-exchange: mint short-lived composite sub/act delegation
	// tokens. The actor agent authenticates with its own token; the subject user
	// token is validated by introspection.
	exchanger := auth.NewTokenExchanger(
		deps.Config.Issuer.URL,
		deps.Config.TokenExchange.AccessTokenLifespan,
		deps.Keystore,
		chainsService,
		revocationStore,
		deps.Pool,
		livePub,
		func(ctx context.Context, token string) (string, bool) {
			p, err := authenticator.AuthenticateActor(ctx, token)
			if err != nil {
				return "", false
			}
			return p.ID, true
		},
		func(ctx context.Context, token string) (string, []string, bool) {
			oas := auth.NewSession("")
			_, ar, err := deps.Provider.IntrospectToken(ctx, token, fosite.AccessToken, oas)
			if err != nil {
				return "", nil, false
			}
			return ar.GetSession().GetSubject(), ar.GetGrantedScopes(), true
		},
	)
	authHandler.SetExchanger(exchanger)
	tokenLimiter := middleware.NewRateLimiter(60, time.Minute, middleware.ClientIP)
	registerLimiter := middleware.NewRateLimiter(10, time.Minute, middleware.ClientIP)

	// Prometheus metrics. Exposes request/latency and delegation-activity counters
	// in the text exposition format. It is unauthenticated by design (scrapers do
	// not carry user sessions); restrict it at the network layer in production.
	r.Handle("/metrics", metrics.Handler())

	// Health checks
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		// Return a generic status to unauthenticated callers; the specific reason
		// goes to the logs so probes don't leak internal state.
		ctx := r.Context()
		notReady := func(reason string) {
			slog.Warn("readiness check failed", "reason", reason)
			http.Error(w, "not ready", http.StatusServiceUnavailable)
		}
		if err := deps.Pool.Ping(ctx); err != nil {
			notReady("database unreachable")
			return
		}
		if deps.Keystore.ActiveKID() == "" {
			notReady("no active signing key")
			return
		}
		var dirty bool
		if err := deps.Pool.QueryRow(ctx, `SELECT dirty FROM schema_migrations LIMIT 1`).Scan(&dirty); err != nil {
			notReady("migrations not applied")
			return
		}
		if dirty {
			notReady("database schema is dirty")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	// OIDC Discovery
	r.Get("/.well-known/openid-configuration", auth.DiscoveryHandler(deps.Config.Issuer.URL))
	r.Get("/.well-known/oauth-authorization-server", auth.AuthServerMetadataHandler(deps.Config.Issuer.URL))
	// NOTE: /.well-known/oauth-protected-resource (RFC 9728) is served by resource
	// servers (the MCP gateway in M6), not by the authorization server — the AS
	// must not advertise itself as the protected resource. The handler lives in
	// internal/mcpauth for the gateway to mount.
	r.Get("/.well-known/jwks.json", auth.JWKSHandler(deps.Keystore.VerifierKeys))
	// Signed revocation feed (Tier B): a TTL-bounded, JWS-signed snapshot of
	// revoked-but-unexpired token ids, signed with the same key as the JWKS, that
	// resource servers pull and check offline (no per-request callback).
	r.Get("/.well-known/revoked", revocation.NewFeed(deps.Pool, deps.Keystore, deps.Config.Issuer.URL).Handler())

	// OAuth2 endpoints. The token endpoint is rate-limited to bound token-mint
	// amplification on the exchange grant.
	r.Get("/oauth2/authorize", authHandler.AuthorizeHandler)
	r.With(tokenLimiter.Middleware).Post("/oauth2/token", authHandler.TokenHandler)
	r.Post("/oauth2/revoke", authHandler.RevokeHandler)
	// Introspection is authenticated so an anonymous caller can't read a
	// delegation token's subject/act-chain/scope.
	r.With(authenticator.Require).Post("/oauth2/introspect", authHandler.IntrospectHandler)
	r.Get("/oauth2/userinfo", authHandler.UserinfoHandler)
	// RFC 7591 dynamic client registration, gated by an initial access token and
	// rate-limited.
	r.With(registerLimiter.Middleware).Post("/oauth2/register", registrar.Register)

	// Delegation consent: a logged-in user grants an agent a scoped, constrained
	// slice of their authority. Protected by SameSite=Lax + an Origin/Referer check
	// + a session-bound CSRF token (sent as X-CSRF-Token by the same-origin client).
	r.Post("/consent/delegate", func(w http.ResponseWriter, r *http.Request) {
		sess, err := sessionManager.Get(r.Context(), r)
		if err != nil {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if !auth.SameOrigin(r) {
			http.Error(w, `{"error":"cross-origin request rejected"}`, http.StatusForbidden)
			return
		}
		if !sessionManager.ValidateCSRF(r, sess) {
			http.Error(w, `{"error":"missing or invalid CSRF token"}`, http.StatusForbidden)
			return
		}
		var req struct {
			AgentID     string                 `json:"agent_id"`
			Scopes      []string               `json:"scopes"`
			Resource    string                 `json:"resource"`
			Constraints delegation.Constraints `json:"constraints"`
			TTLSeconds  int                    `json:"ttl_seconds"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
			return
		}
		var orgID *string
		if err := deps.Pool.QueryRow(r.Context(),
			`SELECT org_id::text FROM agents WHERE id = $1 AND status = 'active'`, req.AgentID).Scan(&orgID); err != nil {
			http.Error(w, `{"error":"agent not found"}`, http.StatusNotFound)
			return
		}
		// The user must belong to the agent's organization to delegate to it, so a
		// user in one tenant cannot grant authority to another tenant's agent.
		if orgID == nil {
			http.Error(w, `{"error":"agent not found"}`, http.StatusNotFound)
			return
		}
		var isMember bool
		if err := deps.Pool.QueryRow(r.Context(),
			`SELECT exists(SELECT 1 FROM org_members WHERE org_id = $1 AND user_id = $2)`,
			*orgID, sess.UserID).Scan(&isMember); err != nil || !isMember {
			http.Error(w, `{"error":"not a member of the agent's organization"}`, http.StatusForbidden)
			return
		}
		org := *orgID
		consentID, delegationID, err := chainsService.GrantConsent(r.Context(), chains.ConsentRequest{
			UserID:      sess.UserID,
			AgentID:     req.AgentID,
			OrgID:       org,
			Scopes:      req.Scopes,
			Constraints: req.Constraints,
			Resource:    req.Resource,
			TTL:         time.Duration(req.TTLSeconds) * time.Second,
		})
		if err != nil {
			http.Error(w, `{"error":"could not record consent"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"consent_id": consentID, "delegation_id": delegationID})
	})

	// Re-delegation: an authenticated agent hands an attenuated slice of a
	// delegation it holds to a sub-agent (multi-hop). The agent authenticates with
	// its own agent token.
	r.With(authenticator.Require).Post("/delegations/redelegate", func(w http.ResponseWriter, r *http.Request) {
		p, ok := authz.FromContext(r.Context())
		if !ok || p.Type != authz.TypeAgent {
			http.Error(w, `{"error":"only an agent may re-delegate"}`, http.StatusForbidden)
			return
		}
		var req struct {
			ParentDelegationID string                 `json:"parent_delegation_id"`
			DelegateeAgentID   string                 `json:"delegatee_agent_id"`
			Scopes             []string               `json:"scopes"`
			Constraints        delegation.Constraints `json:"constraints"`
			TTLSeconds         int                    `json:"ttl_seconds"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
			return
		}
		childID, err := chainsService.Redelegate(r.Context(), req.ParentDelegationID, p.ID,
			req.DelegateeAgentID, req.Scopes, req.Constraints, time.Duration(req.TTLSeconds)*time.Second)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"delegation_id": childID})
	})

	// Login / Registration / Logout UI
	r.Get("/login", consentHandler.LoginPage)
	r.Post("/login", consentHandler.LoginSubmit)
	r.Get("/register", consentHandler.RegisterPage)
	r.Post("/register", consentHandler.RegisterSubmit)
	r.Post("/logout", consentHandler.LogoutHandler)

	// Self-service delegation management (session-authenticated inside the handler).
	r.Get("/account/delegations", accountHandler.Delegations)
	r.Post("/account/delegations/{id}/revoke", accountHandler.Revoke)

	// Superadmin audit/provenance viewer (session + superadmin checked in the handler).
	r.Get("/admin/audit", adminHandler.Audit)

	// Superadmin real-time console: dashboard shell, authority-graph snapshot, and
	// the live SSE activity stream (session + superadmin checked in the handler).
	r.Get("/admin/live", liveHandler.Dashboard)
	r.Get("/admin/live/snapshot", liveHandler.Snapshot)
	r.Get("/admin/live/events", liveHandler.Events)
	r.Post("/admin/live/ingest", liveHandler.Ingest)

	// Root redirect
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusFound)
	})

	// Invitation accept endpoint (public, token-based)
	r.Get("/invitations/accept", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Error(w, "missing token", http.StatusBadRequest)
			return
		}

		// Check for session — user must be logged in to accept
		sess, err := sessionManager.Get(r.Context(), r)
		if err != nil {
			http.Redirect(w, r, "/login?redirect=/invitations/accept?token="+token, http.StatusFound)
			return
		}

		if err := orgService.AcceptInvitation(r.Context(), token, sess.UserID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"message":"invitation accepted"}`)
	})

	// Email verification endpoint
	r.Get("/verify-email", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if err := emailService.VerifyEmail(r.Context(), token); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"message":"email verified"}`)
	})

	// Password reset endpoints
	r.Post("/forgot-password", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		emailAddr := r.FormValue("email")
		emailService.SendPasswordResetEmail(r.Context(), emailAddr)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"message":"if the email exists, a reset link has been sent"}`)
	})

	r.Post("/reset-password", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		token := r.FormValue("token")
		password := r.FormValue("password")
		if err := emailService.ResetPassword(r.Context(), token, password); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"message":"password reset successful"}`)
	})

	// Magic link endpoints
	r.Post("/magic-link", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		emailAddr := r.FormValue("email")
		emailService.SendMagicLink(r.Context(), emailAddr)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"message":"if the email exists, a magic link has been sent"}`)
	})

	r.Get("/magic-login", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		userID, err := emailService.ValidateMagicLink(r.Context(), token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sess, err := sessionManager.Create(r.Context(), userID, r)
		if err != nil {
			http.Error(w, "session error", http.StatusInternalServerError)
			return
		}
		sessionManager.SetCookie(w, sess)
		http.Redirect(w, r, "/", http.StatusFound)
	})

	// SCIM 2.0 — directory sync; superadmin-authenticated until per-tenant
	// provisioning tokens land.
	r.Group(func(r chi.Router) {
		r.Use(authenticator.Require)
		r.Use(authz.RequireSuperadmin)
		r.Mount("/scim/v2", scimHandler.Routes())
	})

	// Admin API — all routes require authentication.
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(authenticator.Require)

		// Global resources that are not yet org-scoped: superadmin only, so an
		// org-admin cannot manage users/clients/keys across tenants.
		r.Group(func(r chi.Router) {
			r.Use(authz.RequireSuperadmin)
			r.Mount("/users", userHandler.Routes())
			r.Mount("/clients", clientHandler.Routes())
			r.Mount("/orgs", orgHandler.Routes())
			r.Mount("/apikeys", apikeyHandler.Routes())
			r.Mount("/audit", audit.NewHandler(deps.Pool).Routes())
			r.Mount("/gateway/upstreams", mcpgw.NewUpstreamHandler(mcpgw.NewUpstreamStore(deps.Pool)).Routes())
		})

		// Org-scoped resources: org owner/admins may manage their own org's
		// agents; the handlers filter by the caller's organizations.
		r.Group(func(r chi.Router) {
			r.Use(authz.RequireAdmin)
			r.Mount("/agents", agentHandler.Routes())
		})
	})
}

func (s *Server) Start() error {
	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	// Feed the live console: hold a dedicated Postgres connection LISTENing for
	// activity events (from this process, the gateway, and any replica) and fan
	// them out to connected SSE clients. Stops when s.bg is cancelled on shutdown.
	go live.Listen(s.bg, s.pool, s.hub)

	errCh := make(chan error, 1)
	go func() {
		slog.Info("legant server starting", "addr", s.httpServer.Addr)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	case sig := <-stop:
		slog.Info("shutting down", "signal", sig)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown error: %w", err)
	}

	s.bgCancel() // stop the live publisher + listener before closing the pool
	s.pool.Close()
	slog.Info("server stopped")
	return nil
}
