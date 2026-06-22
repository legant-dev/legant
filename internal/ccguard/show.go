package ccguard

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/legant-dev/legant/internal/delegation"
	"github.com/legant-dev/legant/sdk"
)

// ShowFromDir loads the JWKS + revocation feed from a guard dir and renders the
// rule carried by tokenFile.
func ShowFromDir(dir, tokenFile string, now time.Time) (string, error) {
	jb, err := os.ReadFile(filepath.Join(dir, "jwks.json"))
	if err != nil {
		return "", fmt.Errorf("read JWKS: %w", err)
	}
	keys, err := sdk.ParseJWKS(jb)
	if err != nil {
		return "", err
	}
	feed, _ := LoadSignedFeedFile(filepath.Join(dir, "feed.jwt"), DefaultIssuer, keys) // best-effort
	tb, err := os.ReadFile(tokenFile)
	if err != nil {
		return "", fmt.Errorf("read token: %w", err)
	}
	return RenderRule(string(tb), keys, feed, now)
}

// rawClaims is the subset of a delegation token decoded for DISPLAY — read
// without verifying the signature so an expired or otherwise-invalid token can
// still be inspected (its validity is reported separately).
type rawClaims struct {
	Issuer   string          `json:"iss"`
	Subject  string          `json:"sub"`
	Audience json.RawMessage `json:"aud"`
	Scope    string          `json:"scope"`
	Act      *actClaim       `json:"act"`
	IssuedAt int64           `json:"iat"`
	Expires  int64           `json:"exp"`
	JTI      string          `json:"jti"`
	Cnst     struct {
		MaxAmount  *float64 `json:"max_amount"`
		Categories []string `json:"categories"`
		Resources  []string `json:"resources"`
		Tools      []string `json:"tools"`
		TimeWindow *struct {
			Weekdays []int  `json:"weekdays"`
			StartMin int    `json:"start_min"`
			EndMin   int    `json:"end_min"`
			TZ       string `json:"tz"`
		} `json:"time_window"`
	} `json:"cnst"`
}

type actClaim struct {
	Sub string    `json:"sub"`
	Act *actClaim `json:"act"`
}

// RenderRule decodes a delegation token and renders the rule it carries as a
// human-readable block: provenance, capabilities, allow/deny rules, time window,
// validity, and (if a feed is supplied) revocation status. Decoding never fails
// on an expired/invalid token — validity is shown as a status line instead.
func RenderRule(tokenStr string, keys map[string]*rsa.PublicKey, feed *SignedFeed, now time.Time) (string, error) {
	tokenStr = trimToken(tokenStr)
	parts := strings.Split(tokenStr, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("not a JWT (need 3 dot-separated segments)")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode token payload: %w", err)
	}
	var c rawClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", fmt.Errorf("parse token claims: %w", err)
	}

	// Validity status (signature + issuer + expiry) via the offline verifier.
	status := "✓ valid"
	if len(keys) == 0 {
		status = "? (no JWKS supplied — signature not checked)"
	} else if _, verr := delegation.NewVerifier(c.Issuer, keys).VerifyAny(tokenStr); verr != nil {
		status = "✗ INVALID — " + verr.Error()
	} else if feed != nil && c.JTI != "" && feed.IsRevoked(c.JTI) {
		status = "✗ REVOKED — token id is on the signed revocation feed"
	}

	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	w("Delegation rule  (status: %s)\n", status)
	w("  on behalf of   %s\n", c.Subject)
	w("  acting agent   %s\n", provenanceOf(c.Subject, c.Act))
	w("  audience       %s\n", audStr(c.Audience))
	w("  capabilities   %s\n", scopeOrNone(c.Scope))
	if c.Cnst.MaxAmount != nil {
		w("  max amount     %g\n", *c.Cnst.MaxAmount)
	}
	if len(c.Cnst.Categories) > 0 {
		w("  categories     %s\n", strings.Join(c.Cnst.Categories, ", "))
	}

	allow, deny := splitRules(c.Cnst.Resources)
	w("  ALLOW\n")
	if len(allow) == 0 {
		w("    (no allow-restriction — capabilities above govern)\n")
	}
	for _, r := range allow {
		w("    + %s\n", r)
	}
	if len(c.Cnst.Tools) > 0 {
		w("    + tools: %s\n", strings.Join(c.Cnst.Tools, ", "))
	}
	w("  DENY (overrides allow)\n")
	if len(deny) == 0 {
		w("    (none)\n")
	}
	for _, r := range deny {
		w("    − %s\n", r)
	}
	if tw := c.Cnst.TimeWindow; tw != nil {
		w("  time window    %02d:%02d–%02d:%02d %s  weekdays=%v\n",
			tw.StartMin/60, tw.StartMin%60, tw.EndMin/60, tw.EndMin%60, orUTC(tw.TZ), tw.Weekdays)
	}
	if c.Expires > 0 {
		exp := time.Unix(c.Expires, 0)
		rem := exp.Sub(now).Round(time.Minute)
		w("  expires        %s  (%s from now)\n", exp.Format(time.RFC3339), rem)
	}
	w("  token id       %s\n", c.JTI)
	return b.String(), nil
}

func provenanceOf(subject string, act *actClaim) string {
	var chain []string
	for a := act; a != nil; a = a.Act {
		chain = append(chain, a.Sub)
	}
	// chain is leaf..root; render root..leaf after the subject
	parts := []string{subject}
	for i := len(chain) - 1; i >= 0; i-- {
		parts = append(parts, chain[i])
	}
	return strings.Join(parts, " → ")
}

// splitRules separates "deny-*" entries from the rest and strips scheme prefixes
// for display (path:/cmd:/host:/deny-path: → readable form).
func splitRules(resources []string) (allow, deny []string) {
	for _, r := range resources {
		if r == denyAllSentinel {
			deny = append(deny, "EVERYTHING (attenuated to nothing)")
			continue
		}
		if strings.HasPrefix(r, "deny-") {
			deny = append(deny, prettyRule(strings.TrimPrefix(r, "deny-")))
		} else {
			allow = append(allow, prettyRule(r))
		}
	}
	sort.Strings(allow)
	sort.Strings(deny)
	return allow, deny
}

func prettyRule(r string) string {
	switch {
	case strings.HasPrefix(r, "path:"):
		return "path " + strings.TrimPrefix(r, "path:")
	case strings.HasPrefix(r, "cmd:"):
		return "command " + strings.TrimPrefix(r, "cmd:")
	case strings.HasPrefix(r, "host:"):
		return "host " + strings.TrimPrefix(r, "host:")
	case strings.HasPrefix(r, "tool:"):
		return "tool " + strings.TrimPrefix(r, "tool:")
	default:
		return r
	}
}

func audStr(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var ss []string
	if json.Unmarshal(raw, &ss) == nil {
		return strings.Join(ss, ", ")
	}
	return string(raw)
}

func orUTC(tz string) string {
	if tz == "" {
		return "UTC"
	}
	return tz
}
