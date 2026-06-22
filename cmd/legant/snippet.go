package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// `legant snippet <framework>` prints a ready-to-paste resource-server integration
// block, and `legant init resource-server --framework X` writes it to a runnable
// starter file. Both wire the SAME drop-in middleware shipped in each SDK package
// (sdk/, clients/typescript, clients/python): FetchJWKS -> NewVerifier(feed) ->
// per-request Verify + Authorize, surfacing Provenance() for audit.

type snippet struct {
	desc string
	ext  string
	body string
}

func snippets() map[string]snippet {
	return map[string]snippet{
		"go-chi":     {"Go + chi router", "go", goChiSnippet},
		"go-nethttp": {"Go + net/http", "go", goNetHTTPSnippet},
		"express":    {"Node + Express", "mjs", expressSnippet},
		"fastify":    {"Node + Fastify", "mjs", fastifySnippet},
		"fastapi":    {"Python + FastAPI", "py", fastapiSnippet},
		"flask":      {"Python + Flask", "py", flaskSnippet},
		"mcp-go":     {"Go self-hosted MCP server", "go", mcpGoSnippet},
	}
}

func frameworkList() string {
	s := snippets()
	names := make([]string, 0, len(s))
	for k := range s {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func fill(body, issuer, audience, jwks, feed string) string {
	r := strings.NewReplacer("{{ISSUER}}", issuer, "{{AUDIENCE}}", audience, "{{JWKS}}", jwks, "{{FEED}}", feed)
	return r.Replace(body)
}

// snippetParams resolves the placeholder values, defaulting the JWKS/feed URLs off
// the issuer.
func snippetParams(issuer, audience, jwks, feed string) (string, string, string, string) {
	if jwks == "" {
		jwks = strings.TrimRight(issuer, "/") + "/.well-known/jwks.json"
	}
	if feed == "" {
		feed = strings.TrimRight(issuer, "/") + "/.well-known/revoked"
	}
	return issuer, audience, jwks, feed
}

func snippetFlags(cmd *cobra.Command, issuer, audience, jwks, feed *string) {
	cmd.Flags().StringVar(issuer, "issuer", "https://legant.example.internal", "your Legant issuer URL")
	cmd.Flags().StringVar(audience, "audience", "https://api.example.internal", "THIS resource server's audience (RFC 8707)")
	cmd.Flags().StringVar(jwks, "jwks-url", "", "JWKS URL (default: <issuer>/.well-known/jwks.json)")
	cmd.Flags().StringVar(feed, "feed-url", "", "revocation feed URL (default: <issuer>/.well-known/revoked)")
}

func snippetCmd() *cobra.Command {
	var issuer, audience, jwks, feed string
	cmd := &cobra.Command{
		Use:   "snippet <framework>",
		Short: "Print a copy-paste resource-server integration for a framework",
		Long:  "Frameworks: " + frameworkList(),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sn, ok := snippets()[args[0]]
			if !ok {
				return fmt.Errorf("unknown framework %q (have: %s)", args[0], frameworkList())
			}
			iss, aud, jw, fd := snippetParams(issuer, audience, jwks, feed)
			fmt.Print(fill(sn.body, iss, aud, jw, fd))
			return nil
		},
	}
	snippetFlags(cmd, &issuer, &audience, &jwks, &feed)
	return cmd
}

func initResourceServerCmd() *cobra.Command {
	var framework, out, issuer, audience, jwks, feed string
	cmd := &cobra.Command{
		Use:   "resource-server",
		Short: "Scaffold a runnable resource-server starter for a framework",
		RunE: func(cmd *cobra.Command, args []string) error {
			sn, ok := snippets()[framework]
			if !ok {
				return fmt.Errorf("unknown --framework %q (have: %s)", framework, frameworkList())
			}
			if out == "" {
				out = "legant_rs." + sn.ext
			}
			if _, err := os.Stat(out); err == nil {
				return fmt.Errorf("%s already exists — refusing to overwrite", out)
			}
			iss, aud, jw, fd := snippetParams(issuer, audience, jwks, feed)
			if err := os.WriteFile(out, []byte(fill(sn.body, iss, aud, jw, fd)), 0o644); err != nil {
				return err
			}
			fmt.Printf("Wrote a %s resource-server starter to %s\n", sn.desc, out)
			return nil
		},
	}
	cmd.Flags().StringVar(&framework, "framework", "", "one of: "+frameworkList())
	cmd.Flags().StringVarP(&out, "out", "o", "", "output file (default: legant_rs.<ext>)")
	snippetFlags(cmd, &issuer, &audience, &jwks, &feed)
	_ = cmd.MarkFlagRequired("framework")
	return cmd
}

const goChiSnippet = `// Legant-protected resource server (Go + chi). go get github.com/legant-dev/legant/sdk
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/legant-dev/legant/sdk"
)

func main() {
	ctx := context.Background()
	keys, err := sdk.FetchJWKS(ctx, "{{JWKS}}")
	if err != nil {
		log.Fatal(err)
	}
	// Pull the signed revocation feed so a revoked token is rejected OFFLINE.
	feed, err := sdk.FetchRevocationFeed(ctx, "{{FEED}}", "{{ISSUER}}", keys)
	if err != nil {
		log.Fatal(err)
	}
	// Default: fail open to TTL if the feed is stale/unreachable. For high
	// assurance add sdk.WithFeedFailClosed(maxStaleness) as another option.
	v := sdk.NewVerifier("{{ISSUER}}", "{{AUDIENCE}}", keys, sdk.WithRevocationFeed(feed))

	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(sdk.Authenticate(v)) // verify the Bearer token, attach Claims
		// Authorize the delegated action per request (scope + the constraint dims).
		r.With(sdk.RequireAction(func(req *http.Request) sdk.Action {
			return sdk.Action{Scope: "warehouse:query", Resource: req.URL.Query().Get("schema")}
		})).Get("/query", func(w http.ResponseWriter, req *http.Request) {
			claims := sdk.MustClaims(req.Context())
			// Provenance() names the human the agent acts for — log it.
			_, _ = w.Write([]byte("ok, asked by " + claims.Provenance() + "\n"))
		})
	})
	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
	// NB: the ` + "`rate`" + ` constraint is enforced at mint time, not here — rely on
	// scope / resource / tool / max_amount / time_window for offline denials.
}
`

const goNetHTTPSnippet = `// Legant-protected resource server (Go + net/http). go get github.com/legant-dev/legant/sdk
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/legant-dev/legant/sdk"
)

func main() {
	ctx := context.Background()
	keys, err := sdk.FetchJWKS(ctx, "{{JWKS}}")
	if err != nil {
		log.Fatal(err)
	}
	feed, err := sdk.FetchRevocationFeed(ctx, "{{FEED}}", "{{ISSUER}}", keys)
	if err != nil {
		log.Fatal(err)
	}
	v := sdk.NewVerifier("{{ISSUER}}", "{{AUDIENCE}}", keys, sdk.WithRevocationFeed(feed))

	query := func(w http.ResponseWriter, req *http.Request) {
		claims := sdk.MustClaims(req.Context())
		if err := claims.Authorize(sdk.Action{Scope: "warehouse:query", Resource: req.URL.Query().Get("schema")}); err != nil {
			http.Error(w, "denied: "+err.Error(), http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte("ok, asked by " + claims.Provenance() + "\n"))
	}
	mux := http.NewServeMux()
	mux.Handle("/query", sdk.Authenticate(v)(http.HandlerFunc(query)))
	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
`

const expressSnippet = `// Legant-protected resource server (Node + Express). npm i @legant/sdk express
import express from 'express';
import {
  Verifier, fetchJWKS, fetchRevocationFeed, expressAuth, expressRequireAction,
} from '@legant/sdk';

const keys = await fetchJWKS('{{JWKS}}');
// Pull the signed revocation feed so a revoked token is rejected offline.
const feed = await fetchRevocationFeed('{{FEED}}', '{{ISSUER}}', keys);
const verifier = new Verifier('{{ISSUER}}', '{{AUDIENCE}}', keys, { feed });
// For high assurance set { feed, feedFailClosedMs } to reject on a stale feed.

const app = express();
app.use(expressAuth(verifier)); // verify the Bearer token, attach req.legant
app.get(
  '/query',
  expressRequireAction((req) => ({ scope: 'warehouse:query', resource: String(req.query.schema ?? '') })),
  (req, res) => res.send('ok, asked by ' + req.legant.provenance()),
);
app.listen(8080, () => console.log('listening on :8080'));
// NB: the 'rate' constraint is mint-time only; rely on the other dims offline.
`

const fastifySnippet = `// Legant-protected resource server (Node + Fastify). npm i @legant/sdk fastify
import Fastify from 'fastify';
import {
  Verifier, fetchJWKS, fetchRevocationFeed, fastifyAuth, fastifyRequireAction,
} from '@legant/sdk';

const keys = await fetchJWKS('{{JWKS}}');
const feed = await fetchRevocationFeed('{{FEED}}', '{{ISSUER}}', keys);
const verifier = new Verifier('{{ISSUER}}', '{{AUDIENCE}}', keys, { feed });

const app = Fastify();
app.addHook('preHandler', fastifyAuth(verifier)); // attaches request.legant
app.get(
  '/query',
  { preHandler: fastifyRequireAction((req) => ({ scope: 'warehouse:query', resource: String(req.query.schema ?? '') })) },
  async (req) => ({ by: req.legant.provenance() }),
);
app.listen({ port: 8080 });
`

const fastapiSnippet = `# Legant-protected resource server (Python + FastAPI). pip install legant-sdk fastapi uvicorn
from fastapi import Depends, FastAPI
from legant_sdk import (
    Action, Claims, Verifier, fastapi_auth, fetch_jwks, fetch_revocation_feed,
)

keys = fetch_jwks("{{JWKS}}")
# Pull the signed revocation feed so a revoked token is rejected offline.
feed = fetch_revocation_feed("{{FEED}}", "{{ISSUER}}", keys)
verifier = Verifier("{{ISSUER}}", "{{AUDIENCE}}", keys, feed=feed)

app = FastAPI()


def query_action(request) -> Action:
    return Action(scope="warehouse:query", resource=request.query_params.get("schema", ""))


@app.get("/query")
def query(claims: Claims = Depends(fastapi_auth(verifier, action=query_action))):
    # claims.provenance() names the human the agent acts for — log it.
    return {"by": claims.provenance()}


# NB: the 'rate' constraint is mint-time only; rely on the other dims offline.
`

const flaskSnippet = `# Legant-protected resource server (Python + Flask). pip install legant-sdk flask
from flask import Flask, g, request
from legant_sdk import Action, Verifier, fetch_jwks, fetch_revocation_feed, flask_require

keys = fetch_jwks("{{JWKS}}")
feed = fetch_revocation_feed("{{FEED}}", "{{ISSUER}}", keys)
verifier = Verifier("{{ISSUER}}", "{{AUDIENCE}}", keys, feed=feed)

app = Flask(__name__)


@app.get("/query")
@flask_require(
    verifier,
    action=lambda req: Action(scope="warehouse:query", resource=request.args.get("schema", "")),
)
def query():
    return {"by": g.legant.provenance()}
`

const mcpGoSnippet = `// Self-hosted MCP server: verify + authorize a tools/call before dispatch.
// (For MCP servers you do NOT control, put them behind the ` + "`legant gateway`" + ` instead.)
package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/legant-dev/legant/sdk"
)

// toolScopes maps each MCP tool to the capability scope it requires.
var toolScopes = map[string]string{
	"kubectl_scale": "deploy:scale",
	"kubectl_logs":  "logs:read",
}

func main() {
	ctx := context.Background()
	keys, _ := sdk.FetchJWKS(ctx, "{{JWKS}}")
	feed, _ := sdk.FetchRevocationFeed(ctx, "{{FEED}}", "{{ISSUER}}", keys)
	v := sdk.NewVerifier("{{ISSUER}}", "{{AUDIENCE}}", keys, sdk.WithRevocationFeed(feed))

	http.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		claims, err := v.Verify(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if err != nil {
			http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if name, err := sdk.MCPToolName(body); err == nil { // it's a tools/call
			if err := claims.Authorize(sdk.Action{Scope: toolScopes[name], Tool: name}); err != nil {
				http.Error(w, "denied: "+err.Error(), http.StatusForbidden)
				return
			}
		}
		// ... dispatch to your MCP server with body ...
		_ = body
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}
`
