package ccguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/legant-dev/legant/sdk"
)

func TestInitLocalProducesUsableSetup(t *testing.T) {
	dir := t.TempDir()
	project := t.TempDir()
	s, err := InitLocal(dir, project, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{s.KeyPath, s.JWKSPath, s.FeedPath, s.Tokens["builder"], s.Tokens["reviewer"], s.Tokens["operator"]} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected file %s: %v", p, err)
		}
	}
	if !strings.Contains(s.SettingsJSON, "legant guard check") {
		t.Fatal("settings block should wire the guard check hook")
	}

	// The builder token verifies under the published JWKS and grants fs.write.
	jb, _ := os.ReadFile(s.JWKSPath)
	keys, err := sdk.ParseJWKS(jb)
	if err != nil {
		t.Fatal(err)
	}
	tb, _ := os.ReadFile(s.Tokens["builder"])
	claims, err := sdk.NewVerifier(DefaultIssuer, DefaultAudience, keys).Verify(trimToken(string(tb)))
	if err != nil {
		t.Fatalf("builder token should verify: %v", err)
	}
	if !strings.Contains(claims.Scope, "fs.write") {
		t.Fatalf("builder scope = %q, want fs.write", claims.Scope)
	}
}

func TestMintChildTokenAttenuatesAndRefusesEscalation(t *testing.T) {
	dir := t.TempDir()
	project := t.TempDir()
	s, err := InitLocal(dir, project, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	parent := s.Tokens["builder"] // fs.read fs.write shell.exec

	// Attenuate to read-only: succeeds, scope narrows, provenance extends.
	childTok, err := MintChildToken(dir, parent, "agent:doc-writer", []string{"fs.read"}, 30*time.Minute, time.Now())
	if err != nil {
		t.Fatalf("child mint: %v", err)
	}
	jb, _ := os.ReadFile(s.JWKSPath)
	keys, _ := sdk.ParseJWKS(jb)
	claims, err := sdk.NewVerifier(DefaultIssuer, DefaultAudience, keys).Verify(childTok)
	if err != nil {
		t.Fatalf("child token should verify: %v", err)
	}
	if strings.Contains(claims.Scope, "fs.write") {
		t.Fatalf("child should NOT have fs.write, got scope %q", claims.Scope)
	}
	if !strings.Contains(claims.Provenance(), "agent:builder -> agent:doc-writer") {
		t.Fatalf("child provenance should record the chain, got %q", claims.Provenance())
	}

	// Escalation: request a scope the parent lacks → refused at mint.
	if _, err := MintChildToken(dir, parent, "agent:rogue", []string{"net.fetch"}, time.Hour, time.Now()); err == nil {
		t.Fatal("expected escalation to net.fetch to be refused")
	}
}

func TestRevokeJTIPublishesFeed(t *testing.T) {
	dir := t.TempDir()
	project := t.TempDir()
	s, err := InitLocal(dir, project, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tb, _ := os.ReadFile(s.Tokens["builder"])
	jti := JTIOf(trimToken(string(tb)))

	ver, err := RevokeJTI(dir, jti, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if ver != 2 {
		t.Fatalf("expected feed version 2 after first revoke, got %d", ver)
	}
	jb, _ := os.ReadFile(s.JWKSPath)
	keys, _ := sdk.ParseJWKS(jb)
	feed, err := LoadSignedFeedFile(s.FeedPath, DefaultIssuer, keys)
	if err != nil {
		t.Fatal(err)
	}
	if !feed.IsRevoked(jti) {
		t.Fatal("expected the builder jti to be on the feed after revoke")
	}
}

func TestFeedPostureFromEnv(t *testing.T) {
	dir := t.TempDir()
	project := t.TempDir()
	s, err := InitLocal(dir, project, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvTokenFile, s.Tokens["builder"])
	t.Setenv(EnvJWKS, s.JWKSPath)
	t.Setenv(EnvIssuer, DefaultIssuer)
	t.Setenv(EnvAudience, DefaultAudience)

	// A CONFIGURED feed that cannot be loaded (deleted/corrupt/expired) is a tamper
	// or staleness signal and must fail CLOSED — not silently disable revocation.
	t.Setenv(EnvFeed, filepath.Join(dir, "does-not-exist.jwt"))
	cfg, enabled, err := LoadConfigFromEnv()
	if err != nil || !enabled {
		t.Fatalf("expected enabled config, got enabled=%v err=%v", enabled, err)
	}
	if cfg.DenyAll == "" {
		t.Fatal("a configured-but-unloadable feed must fail CLOSED (DenyAll set)")
	}
	if !NewGuard(cfg).Decide(call("Read", `{"file_path":"x"}`)).Block {
		t.Fatal("DenyAll guard should block every call")
	}

	// A valid feed loads and does not deny-all; the self-protect set covers the
	// guard's own files.
	t.Setenv(EnvFeed, s.FeedPath)
	cfg2, _, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.DenyAll != "" {
		t.Fatalf("a valid feed should not deny-all: %q", cfg2.DenyAll)
	}
	if len(cfg2.SelfProtect) == 0 {
		t.Fatal("self-protect paths should be populated from the configured files")
	}
}

// TestSelfProtectionBlocksTamper proves an agent cannot touch the guard's own
// trust material even when its path roots would otherwise allow it.
func TestSelfProtectionBlocksTamper(t *testing.T) {
	h := newHarness(t)
	// A permissive token (wildcard, no roots) — only self-protect should stop it.
	g := BuiltinRoles("/work/project")["operator"].Grant("user:alice", "agent:op", time.Hour, time.Now())
	guardDir := "/home/user/.config/legant/guard/proj"
	cfg := Config{
		Token: h.mint(t, g, testAud), Issuer: testIssuer, Audience: testAud, Keys: h.keys,
		SelfProtect: []string{guardDir + "/feed.jwt", guardDir + "/key.pem", guardDir, "/work/project/.claude"},
	}
	guard := NewGuard(cfg)
	mustBlock(t, guard.Decide(call("Write", `{"file_path":"`+guardDir+`/feed.jwt","content":"x"}`)), "denied")
	mustBlock(t, guard.Decide(call("Read", `{"file_path":"`+guardDir+`/key.pem"}`)), "denied")
	mustBlock(t, guard.Decide(call("Write", `{"file_path":"/work/project/.claude/settings.json","content":"x"}`)), "denied")
	// But ordinary project files are still fine.
	mustAllow(t, guard.Decide(call("Write", `{"file_path":"/work/project/src/app.go","content":"x"}`)))
}
