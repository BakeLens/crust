package rules

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/BakeLens/crust/internal/pathutil"
)

// TestBuiltinRulesLoad verifies all 24 builtin security rules can be loaded.
// Tests rule: protect-env-files
// Tests rule: protect-ssh-keys
// Tests rule: protect-system-auth
// Tests rule: protect-crust
// Tests rule: protect-shell-history
// Tests rule: protect-cloud-credentials
// Tests rule: protect-gpg-keys
// Tests rule: protect-browser-data
// Tests rule: protect-git-credentials
// Tests rule: protect-package-tokens
// Tests rule: protect-shell-rc
// Tests rule: protect-ssh-authorized-keys
// Tests rule: protect-desktop-app-tokens
// Tests rule: protect-os-keychains
// Tests rule: protect-github-cli
// Tests rule: detect-private-key-write
// Tests rule: block-eval-exec
// Tests rule: protect-system-config
// Tests rule: protect-persistence
// Tests rule: detect-reverse-shell
// Tests rule: block-ssrf-metadata
// NOTE: protect-crust-api is hardcoded in engine.go (not a YAML rule)
func TestBuiltinRulesLoad(t *testing.T) {
	loader := NewLoader("")
	rules, err := loader.LoadBuiltin()
	if err != nil {
		t.Fatalf("Failed to load builtin rules: %v", err)
	}

	if len(rules) == 0 {
		t.Error("Expected at least one builtin rule")
	}

	// Check for critical security rules for personal users
	expectedRules := []string{
		"protect-env-files",
		"protect-ssh-keys",
		"protect-system-auth",
		"protect-crust",
		"protect-shell-history",
		"protect-cloud-credentials",
		"protect-gpg-keys",
		"protect-browser-data",
		"protect-git-credentials",
		"protect-package-tokens",
		"protect-shell-rc",
		"protect-ssh-authorized-keys",
		"protect-desktop-app-tokens",
		"protect-os-keychains",
		"protect-github-cli",
		"detect-private-key-write",
		"block-eval-exec",
		"protect-system-config",
		"protect-persistence",
		"detect-reverse-shell",
		"block-ssrf-metadata",
		"protect-agent-config",
		"protect-vscode-settings",
		"protect-git-hooks",
	}

	ruleNames := make(map[string]bool)
	for _, r := range rules {
		ruleNames[r.Name] = true
	}

	for _, name := range expectedRules {
		if !ruleNames[name] {
			t.Errorf("Missing expected builtin rule: %s", name)
		}
	}

	t.Logf("Loaded %d builtin rules", len(rules))
}

// TestLockedRulesSurviveDisableBuiltin verifies that locked rules remain active
// when --disable-builtin is set, while unlocked rules are removed.
func TestLockedRulesSurviveDisableBuiltin(t *testing.T) {
	loader := NewLoader("")
	rules, err := loader.LoadBuiltin()
	if err != nil {
		t.Fatalf("Failed to load builtin rules: %v", err)
	}

	// Verify locked rules exist
	lockedNames := []string{
		"protect-ssh-keys",
		"protect-system-auth",
		"protect-crust",
		"protect-shell-history",
		"protect-cloud-credentials",
		"protect-gpg-keys",
		"protect-git-credentials",
		"protect-ssh-authorized-keys",
		"protect-desktop-app-tokens",
		"protect-os-keychains",
		"protect-system-config",
		"protect-persistence",
		"detect-reverse-shell",
		"block-ssrf-metadata",
		"protect-agent-config",
		"protect-git-hooks",
		"protect-env-files",
		"protect-browser-data",
		"protect-package-tokens",
		"protect-shell-rc",
		"protect-github-cli",
	}
	unlockedNames := []string{
		"detect-private-key-write",
		"block-eval-exec",
		"protect-vscode-settings",
	}

	for _, r := range rules {
		for _, name := range lockedNames {
			if r.Name == name && !r.IsLocked() {
				t.Errorf("Rule %s should be locked", name)
			}
		}
		for _, name := range unlockedNames {
			if r.Name == name && r.IsLocked() {
				t.Errorf("Rule %s should NOT be locked", name)
			}
		}
	}

	// Simulate --disable-builtin: filter to locked only
	var locked []Rule
	for _, r := range rules {
		if r.IsLocked() {
			locked = append(locked, r)
		}
	}

	if len(locked) != len(lockedNames) {
		t.Errorf("Expected %d locked rules, got %d", len(lockedNames), len(locked))
	}

	lockedSet := make(map[string]bool)
	for _, r := range locked {
		lockedSet[r.Name] = true
	}

	for _, name := range lockedNames {
		if !lockedSet[name] {
			t.Errorf("Locked rule %s missing after filter", name)
		}
	}
	for _, name := range unlockedNames {
		if lockedSet[name] {
			t.Errorf("Unlocked rule %s should have been filtered out", name)
		}
	}

	t.Logf("Locked rules surviving --disable-builtin: %d/%d", len(locked), len(rules))
}

// TestDynamicProtectionRulesSurviveDisableBuiltin verifies that the 3 dynamic
// self-protection rules (rules-dir delete, rule-file write, socket access)
// remain active when --disable-builtin is set.
func TestDynamicProtectionRulesSurviveDisableBuiltin(t *testing.T) {
	rulesDir := t.TempDir()
	engine, err := NewEngine(context.Background(), EngineConfig{
		DisableBuiltin: true,
		UserRulesDir:   rulesDir,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Use pathutil.ToSlash to normalize Windows backslash paths to forward
	// slashes. Backslashes break both JSON encoding (C:\U → invalid escape)
	// and bash parsing (the shell AST treats \ as an escape character).
	rulesDirSlash := pathutil.ToSlash(rulesDir)
	deleteArgs, _ := json.Marshal(map[string]string{"command": "rm -rf " + rulesDirSlash + "/foo"})
	writeArgs, _ := json.Marshal(map[string]string{"file_path": rulesDirSlash + "/evil.yaml", "content": "x"})

	tests := []struct {
		name     string
		toolCall ToolCall
	}{
		{
			name: "block-crust-rules-dir-delete",
			toolCall: ToolCall{
				Name:      "Bash",
				Arguments: deleteArgs,
			},
		},
		{
			name: "block-crust-rule-file-write",
			toolCall: ToolCall{
				Name:      "Write",
				Arguments: writeArgs,
			},
		},
		{
			name: "block-crust-socket-access",
			toolCall: ToolCall{
				Name:      "Read",
				Arguments: []byte(`{"file_path":"/home/user/.crust/crust-api-12345.sock"}`),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.Evaluate(tt.toolCall)
			if !result.Matched || result.Action != ActionBlock {
				t.Errorf("Dynamic rule %s should block with DisableBuiltin=true, got matched=%v action=%v",
					tt.name, result.Matched, result.Action)
			}
		})
	}
}
