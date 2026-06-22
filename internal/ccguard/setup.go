package ccguard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	legantcrypto "github.com/legant-dev/legant/internal/crypto"
	"github.com/legant-dev/legant/internal/delegation"
	"github.com/legant-dev/legant/sdk"
)

// LocalKID names the local demo signing key written by InitLocal.
const LocalKID = "legant-guard-local"

// DefaultGuardDir returns a per-project guard directory OUTSIDE the project, under
// the user's config dir — so the guard's key/feed/token are never inside a path
// root the tokens grant (which would let an agent tamper with its own leash).
func DefaultGuardDir(projectRoot string) string {
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		if h, herr := os.UserHomeDir(); herr == nil {
			base = filepath.Join(h, ".config")
		} else {
			base = os.TempDir()
		}
	}
	name := filepath.Base(projectRoot)
	if name == "" || name == "/" || name == "." {
		name = "default"
	}
	return filepath.Join(base, "legant", "guard", name)
}

// localFeedTTL is how long a locally-published feed file stays valid. The static
// file is only rewritten by `guard init` / `guard revoke`; it is given a moderate
// validity window — long enough to avoid spurious expiry between revocations,
// short enough to bound a rolled-back-feed replay. On expiry the guard fails
// CLOSED (re-run `guard init` to refresh).
const localFeedTTL = 14 * 24 * time.Hour

// LocalSetup is the set of files InitLocal produced and the wiring it suggests.
type LocalSetup struct {
	Dir          string
	KeyPath      string
	JWKSPath     string
	FeedPath     string
	AuditPath    string
	Tokens       map[string]string // role -> token file path
	SettingsJSON string            // a ready .claude/settings.json hook block
}

// InitLocal writes a self-contained, OFFLINE guard setup under dir: a local
// signing key, its JWKS, an empty signed revocation feed, and one token per
// built-in role for projectRoot. It returns the file layout plus a
// .claude/settings.json hook block (with the env wired inline) so the result can
// be dropped straight into a project. The private key is a LOCAL DEMO key — in a
// real deployment the token comes from a token-exchange against your Legant
// issuer and the JWKS/feed are the issuer's published endpoints.
func InitLocal(dir, projectRoot string, ttl time.Duration, now time.Time) (*LocalSetup, error) {
	abs := func(p string) string { a, _ := filepath.Abs(p); return a }
	projectRoot = abs(projectRoot)
	if dir == "" {
		dir = DefaultGuardDir(projectRoot)
	}
	dir = abs(dir)
	// The guard's trust material (signing key, feed, tokens) must NOT live inside a
	// path root the tokens grant — the builtin roles grant the project root, so a
	// guard dir inside the project would let a write-capable agent roll back its own
	// revocation or read the signing key. Refuse that layout outright.
	if contained(dir, []string{projectRoot}) {
		return nil, fmt.Errorf("guard dir %q is inside the project root %q — choose a dir OUTSIDE the project so an agent cannot tamper with its own key/feed (default: %s)", dir, projectRoot, DefaultGuardDir(projectRoot))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}

	key, err := legantcrypto.GenerateRSAKey(2048)
	if err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, "key.pem")
	if err := SavePrivateKey(keyPath, key); err != nil {
		return nil, err
	}
	jwks, err := BuildJWKS(LocalKID, &key.PublicKey)
	if err != nil {
		return nil, err
	}
	jwksPath := filepath.Join(dir, "jwks.json")
	if err := os.WriteFile(jwksPath, jwks, 0o600); err != nil {
		return nil, err
	}
	feedTok, err := BuildSignedFeed(nil, 1, DefaultIssuer, LocalKID, key, localFeedTTL, now)
	if err != nil {
		return nil, err
	}
	feedPath := filepath.Join(dir, "feed.jwt")
	if err := os.WriteFile(feedPath, []byte(feedTok), 0o600); err != nil {
		return nil, err
	}

	signer := delegation.NewSigner(DefaultIssuer, LocalKID, key)
	tokens := map[string]string{}
	for name, role := range BuiltinRoles(projectRoot) {
		g := role.Grant("user:local", "agent:"+name, ttl, now)
		tok, _, err := MintGrant(signer, g, DefaultAudience, now)
		if err != nil {
			return nil, err
		}
		p := filepath.Join(dir, name+".jwt")
		if err := os.WriteFile(p, []byte(tok), 0o600); err != nil {
			return nil, err
		}
		tokens[name] = p
	}

	auditPath := filepath.Join(dir, "audit.jsonl")
	settings := settingsBlock(tokens["builder"], jwksPath, feedPath, auditPath)
	return &LocalSetup{
		Dir: dir, KeyPath: keyPath, JWKSPath: jwksPath, FeedPath: feedPath,
		AuditPath: auditPath, Tokens: tokens, SettingsJSON: settings,
	}, nil
}

// MintRoleToken mints a fresh token for a built-in role using the local key.
func MintRoleToken(dir, roleName, user, agent, projectRoot string, ttl time.Duration, now time.Time) (string, error) {
	role, ok := BuiltinRoles(absOrSame(projectRoot))[roleName]
	if !ok {
		return "", fmt.Errorf("unknown role %q (have: reviewer, builder, operator)", roleName)
	}
	key, err := LoadPrivateKey(filepath.Join(dir, "key.pem"))
	if err != nil {
		return "", err
	}
	signer := delegation.NewSigner(DefaultIssuer, LocalKID, key)
	if agent == "" {
		agent = "agent:" + roleName
	}
	g := role.Grant(user, agent, ttl, now)
	tok, _, err := MintGrant(signer, g, DefaultAudience, now)
	return tok, err
}

// MintChildToken mints an ATTENUATED child token from a parent token — the
// offline analog of a Claude Code sub-agent receiving a narrower slice of its
// parent's authority. It verifies the parent under the local key, intersects the
// requested scopes against the parent's (a child can never widen), tightens
// constraints, extends the sub/act provenance chain with childAgent, and clamps
// expiry to the parent's. Requesting a scope the parent lacks yields an error —
// escalation is impossible by construction.
func MintChildToken(dir, parentTokenFile, childAgent string, requestedScopes []string, ttl time.Duration, now time.Time) (string, error) {
	key, err := LoadPrivateKey(filepath.Join(dir, "key.pem"))
	if err != nil {
		return "", err
	}
	jwks, err := os.ReadFile(filepath.Join(dir, "jwks.json"))
	if err != nil {
		return "", err
	}
	keys, err := sdk.ParseJWKS(jwks)
	if err != nil {
		return "", err
	}
	ptBytes, err := os.ReadFile(parentTokenFile)
	if err != nil {
		return "", err
	}
	parent, err := delegation.NewVerifier(DefaultIssuer, keys).VerifyAny(trimToken(string(ptBytes)))
	if err != nil {
		return "", fmt.Errorf("parent token invalid: %w", err)
	}

	parentScopes := strings.Fields(parent.Scope)
	child := delegation.Attenuate(parentScopes, requestedScopes)
	if len(child) == 0 {
		return "", fmt.Errorf("requested scopes %v are not a subset of the parent's %v", requestedScopes, parentScopes)
	}
	if len(child) != len(requestedScopes) {
		return "", fmt.Errorf("requested scopes %v exceed the parent's authority %v (escalation refused)", requestedScopes, parentScopes)
	}

	var parentCnst delegation.Constraints
	if parent.Constraints != nil {
		parentCnst = *parent.Constraints
	}
	tightened := delegation.Tighten(parentCnst, delegation.Constraints{})

	if childAgent == "" {
		childAgent = "agent:subagent"
	}
	childAct := &delegation.ActClaim{Sub: childAgent, Act: parent.Act}

	exp := now.Add(ttl)
	if pexp := parent.ExpiresAt; pexp != nil && exp.After(pexp.Time) {
		exp = pexp.Time
	}

	signer := delegation.NewSigner(DefaultIssuer, LocalKID, key)
	return signer.IssueClaims(parent.Subject, childAct, child, DefaultAudience, &tightened, exp, now)
}

// RevokeJTI republishes the local feed with jti added, bumping the version. It
// preserves the ids already on the feed.
func RevokeJTI(dir, jti string, now time.Time) (int64, error) {
	key, err := LoadPrivateKey(filepath.Join(dir, "key.pem"))
	if err != nil {
		return 0, err
	}
	jwks, err := os.ReadFile(filepath.Join(dir, "jwks.json"))
	if err != nil {
		return 0, err
	}
	keys, err := sdk.ParseJWKS(jwks)
	if err != nil {
		return 0, err
	}
	feedPath := filepath.Join(dir, "feed.jwt")
	cur, err := LoadSignedFeedFile(feedPath, DefaultIssuer, keys)
	if err != nil {
		return 0, err
	}
	jtis := cur.RevokedJTIs()
	if !containsStr(jtis, jti) {
		jtis = append(jtis, jti)
	}
	version := cur.Version() + 1
	tok, err := BuildSignedFeed(jtis, version, DefaultIssuer, LocalKID, key, localFeedTTL, now)
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(feedPath, []byte(tok), 0o600); err != nil {
		return 0, err
	}
	return version, nil
}

func absOrSame(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

func settingsBlock(tokenFile, jwksPath, feedPath, auditPath string) string {
	cmd := fmt.Sprintf(
		"LEGANT_GUARD_TOKEN_FILE=%q LEGANT_GUARD_JWKS=%q LEGANT_GUARD_FEED=%q LEGANT_GUARD_AUDIT=%q legant guard check",
		tokenFile, jwksPath, feedPath, auditPath)
	return `{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": ` + jsonString(cmd) + ` }
        ]
      }
    ]
  }
}`
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
