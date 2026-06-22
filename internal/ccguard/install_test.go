package ccguard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallWiresAllAgentsAndUninstalls(t *testing.T) {
	project := t.TempDir()
	dir := t.TempDir()

	res, err := Install(InstallOptions{
		Dir: dir, Project: project, Role: "open", Binary: "/usr/local/bin/legant",
		Tools: []string{"claude-code", "codex", "opencode"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 3 {
		t.Fatalf("expected 3 installs, got %d", len(res))
	}

	// Claude Code + Codex: valid JSON with a Legant PreToolUse command.
	for _, rel := range []string{".claude/settings.local.json", ".codex/hooks.json"} {
		b, err := os.ReadFile(filepath.Join(project, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		var root map[string]any
		if err := json.Unmarshal(b, &root); err != nil {
			t.Fatalf("%s is not valid JSON: %v", rel, err)
		}
		if !strings.Contains(string(b), "guard check") || !strings.Contains(string(b), "LEGANT_GUARD_TOKEN_FILE") {
			t.Fatalf("%s should wire the guard check command", rel)
		}
	}

	// opencode: a plugin that shells to the binary and gates tool.execute.before.
	plugin, err := os.ReadFile(filepath.Join(project, ".opencode/plugin/legant-guard.ts"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"tool.execute.before", "/usr/local/bin/legant", "guard", "check", "r.status === 2"} {
		if !strings.Contains(string(plugin), want) {
			t.Fatalf("opencode plugin missing %q", want)
		}
	}

	// Idempotency: re-install claude-code keeps exactly one PreToolUse block.
	if _, err := Install(InstallOptions{Dir: dir, Project: project, Role: "open", Binary: "/usr/local/bin/legant", Tools: []string{"claude-code"}}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(project, ".claude/settings.local.json"))
	var root map[string]any
	_ = json.Unmarshal(b, &root)
	pre := root["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre) != 1 {
		t.Fatalf("re-install should not duplicate the block, got %d", len(pre))
	}

	// Uninstall clears every location.
	removed := Uninstall(project)
	if len(removed) < 2 {
		t.Fatalf("uninstall should remove the hooks, removed %d", len(removed))
	}
	if _, err := os.Stat(filepath.Join(project, ".opencode/plugin/legant-guard.ts")); !os.IsNotExist(err) {
		t.Fatal("opencode plugin should be removed")
	}
	cb, _ := os.ReadFile(filepath.Join(project, ".claude/settings.local.json"))
	if strings.Contains(string(cb), "LEGANT_GUARD") {
		t.Fatal("claude settings should no longer reference the guard")
	}
}

// TestInstallPreservesOtherSettings ensures the merge never clobbers unrelated keys.
func TestInstallPreservesOtherSettings(t *testing.T) {
	project := t.TempDir()
	dir := t.TempDir()
	claudeDir := filepath.Join(project, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	existing := `{"model":"opus","permissions":{"allow":["Read"]},"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo hi"}]}]}}`
	if err := os.WriteFile(filepath.Join(claudeDir, "settings.local.json"), []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(InstallOptions{Dir: dir, Project: project, Role: "open", Binary: "legant", Tools: []string{"claude-code"}}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(claudeDir, "settings.local.json"))
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	if root["model"] != "opus" {
		t.Fatal("install clobbered the existing 'model' setting")
	}
	pre := root["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre) != 2 { // the pre-existing echo block + ours
		t.Fatalf("expected the existing hook to be preserved alongside ours, got %d blocks", len(pre))
	}
}
