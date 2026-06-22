package ccguard

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/legant-dev/legant/internal/delegation"
)

// Role is a named bundle of capabilities for a Claude Code agent. Roles compile
// down to a Legant delegation grant: Scopes become the token's capability scopes;
// PathRoots / Commands / Hosts become "path:" / "cmd:" / "host:" ALLOW entries;
// and DenyPaths / DenyCommands / DenyHosts / DenyTools become "deny-*" entries
// that OVERRIDE allow — letting a role say "allow everything EXCEPT X".
type Role struct {
	Name        string
	Description string
	Scopes      []string // capability verbs: fs.read fs.write shell.exec net.fetch mcp.call agent.spawn (or "*")
	Tools       []string // optional explicit Claude Code tool allow-list
	PathRoots   []string // filesystem roots the agent may touch
	Commands    []string // shell executables the agent may run
	Hosts       []string // hosts the agent may fetch from
	DenyPaths   []string // paths refused even inside an allowed root
	DenyCmds    []string // commands refused even when shell.exec is granted
	DenyHosts   []string // hosts refused even within an allowed host
	DenyTools   []string // Claude Code tools refused outright
}

// BuiltinRoles are ready-to-use roles. NOTE: shell.exec cannot be path-contained
// (see the package doc), so the only role with HARD filesystem containment is
// `reviewer` (no shell). `builder` grants shell but with a tight command
// allow-list (no interpreters/network tools) plus tripwires; `open` shows the
// "allow everything except" pattern; `operator` is the unrestricted escape hatch.
func BuiltinRoles(projectRoot string) map[string]Role {
	// Defaults applied to any role that can write or run commands.
	sensitivePaths := []string{".env", ".env.local", ".git/config", ".ssh", ".aws", ".npmrc"}
	exfilCmds := []string{"curl", "wget", "ssh", "scp", "nc", "ncat", "telnet"}
	return map[string]Role{
		"reviewer": {
			Name:        "reviewer",
			Description: "read-only, hard-contained: inspect the project, run nothing, write nothing",
			Scopes:      []string{"fs.read"},
			PathRoots:   []string{projectRoot},
		},
		"builder": {
			Name:        "builder",
			Description: "read/write within the project and run safe build/VCS commands (no interpreters, no network)",
			Scopes:      []string{"fs.read", "fs.write", "shell.exec"},
			PathRoots:   []string{projectRoot},
			Commands:    []string{"go", "gofmt", "git", "make", "ls", "cat", "grep", "rg", "find", "test", "echo", "mkdir", "cp", "mv", "touch", "sed", "diff"},
			DenyPaths:   sensitivePaths,
			DenyCmds:    exfilCmds,
		},
		"open": {
			Name:        "open",
			Description: "allow everything EXCEPT secrets and network/exfil commands — the granular rule editors can't express",
			Scopes:      []string{"*"},
			DenyPaths:   sensitivePaths,
			DenyCmds:    exfilCmds,
		},
		"operator": {
			Name:        "operator",
			Description: "unrestricted escape hatch (wildcard, no denies) — audited like any other",
			Scopes:      []string{"*"},
		},
	}
}

// Grant turns a role into a root delegation grant: user delegates to agent.
func (r Role) Grant(user, agent string, ttl time.Duration, now time.Time) *delegation.Grant {
	return delegation.NewRootGrant(user, agent, r.Scopes, r.constraints(), ttl, now)
}

func (r Role) constraints() delegation.Constraints {
	var res []string
	add := func(prefix string, vals []string) {
		for _, v := range vals {
			res = append(res, prefix+v)
		}
	}
	add("path:", r.PathRoots)
	add("cmd:", r.Commands)
	add("host:", r.Hosts)
	add("deny-path:", r.DenyPaths)
	add("deny-cmd:", r.DenyCmds)
	add("deny-host:", r.DenyHosts)
	add("deny-tool:", r.DenyTools)
	return delegation.Constraints{Tools: r.Tools, Resources: res}
}

// MintGrant signs a delegation token for a grant, bound to the guard audience.
// It uses IssueClaims (not IssueForGrant) precisely because the guard overloads
// the resource list for "path:"/"cmd:" rules rather than RFC 8707 audiences, so
// the audience must not be required to appear in that list. The full sub/act
// provenance of the chain is preserved, so a sub-agent token records its parents.
func MintGrant(signer *delegation.Signer, g *delegation.Grant, audience string, now time.Time) (token, jti string, err error) {
	var act *delegation.ActClaim
	for _, a := range g.ActorChainRootToLeaf() {
		act = &delegation.ActClaim{Sub: a, Act: act}
	}
	cnst := g.Constraints
	token, err = signer.IssueClaims(g.RootDelegator(), act, g.Scopes, audience, &cnst, g.ExpiresAt, now)
	if err != nil {
		return "", "", err
	}
	return token, JTIOf(token), nil
}

// JTIOf reads the jti from a freshly-minted token without re-verifying it (the
// signature was just produced locally).
func JTIOf(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		JTI string `json:"jti"`
	}
	_ = json.Unmarshal(raw, &c)
	return c.JTI
}

// ---- local key material (for the offline `legant guard` demo/setup) ----------

// BuildJWKS renders a single-key RSA JWKS document the guard (and the SDK) can
// verify against — the public half of the local demo key.
func BuildJWKS(kid string, pub *rsa.PublicKey) ([]byte, error) {
	e := big.NewInt(int64(pub.E)).Bytes()
	doc := map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": kid,
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(e),
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}

// SavePrivateKey writes an RSA private key as PKCS#1 PEM (local demo key only).
func SavePrivateKey(path string, key *rsa.PrivateKey) error {
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o600)
}

// LoadPrivateKey reads a PKCS#1 PEM private key written by SavePrivateKey.
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
