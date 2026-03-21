package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/BakeLens/crust/internal/rules"
)

func TestNewSandboxPlugin_NotFound(t *testing.T) {
	// Use an empty PATH so bakelens-sandbox can't be found.
	t.Setenv("PATH", "")

	_, err := NewSandboxPlugin()
	if err == nil {
		t.Fatal("expected error when binary not on PATH")
	}
}

func TestNewSandboxPlugin_Available(t *testing.T) {
	if _, err := exec.LookPath("bakelens-sandbox"); err != nil {
		t.Skip("bakelens-sandbox not installed")
	}
	sp, err := NewSandboxPlugin()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sp.BinaryPath() == "" {
		t.Fatal("expected non-empty binary path")
	}
}

func TestSandboxPlugin_Name(t *testing.T) {
	sp := &SandboxPlugin{binaryPath: "/usr/bin/bakelens-sandbox"}
	if sp.Name() != "sandbox" {
		t.Fatalf("expected name 'sandbox', got %q", sp.Name())
	}
}

func TestSandboxPlugin_SkipNonCommand(t *testing.T) {
	sp := &SandboxPlugin{binaryPath: "/usr/bin/bakelens-sandbox"}
	result := sp.Evaluate(context.Background(), Request{
		ToolName: "Read",
		Command:  "", // not an executable tool call
	})
	if result != nil {
		t.Fatalf("expected nil for non-command request, got %+v", result)
	}
}

func TestSandboxPlugin_BuildPolicy(t *testing.T) {
	sp := &SandboxPlugin{
		binaryPath: "/usr/bin/bakelens-sandbox",
		config: SandboxConfig{
			ExtraPorts: map[string][]int{"tcp": {8080, 443}},
			Resources:  &ResourcePolicy{MemoryLimitMB: new(512)},
		},
	}

	req := Request{
		ToolName: "Bash",
		Command:  "curl https://example.com -o /tmp/file",
		Rules: []RuleSnapshot{
			{
				Name:        "block-ssh",
				Enabled:     true,
				Actions:     []rules.Operation{rules.OpRead, rules.OpWrite},
				BlockPaths:  []string{"/home/user/.ssh/**"},
				BlockExcept: []string{"/home/user/.ssh/config"},
			},
			{
				Name:       "block-evil",
				Enabled:    true,
				BlockHosts: []string{"evil.com", "malware.org"},
			},
			{
				Name:       "disabled-rule",
				Enabled:    false,
				BlockPaths: []string{"/etc/**"},
			},
			{
				Name:       "mixed-rule",
				Enabled:    true,
				BlockPaths: []string{"/var/secrets/**"},
				BlockHosts: []string{"internal.corp"},
				Actions:    []rules.Operation{rules.OpRead},
			},
		},
	}

	policy := sp.BuildPolicy(req)

	// Check version.
	if policy.Version != 1 {
		t.Fatalf("expected version 1, got %d", policy.Version)
	}

	// Check command splitting.
	expected := []string{"curl", "https://example.com", "-o", "/tmp/file"}
	if len(policy.Command) != len(expected) {
		t.Fatalf("expected %d command parts, got %d", len(expected), len(policy.Command))
	}
	for i, e := range expected {
		if policy.Command[i] != e {
			t.Errorf("command[%d]: expected %q, got %q", i, e, policy.Command[i])
		}
	}

	// Check rules: disabled rule should be excluded.
	// block-ssh -> 1 fs rule, block-evil -> 1 network rule, mixed-rule -> 1 fs + 1 network = 4 total
	if len(policy.Rules) != 4 {
		t.Fatalf("expected 4 deny rules, got %d: %+v", len(policy.Rules), policy.Rules)
	}

	// Verify first rule (block-ssh filesystem).
	r0 := policy.Rules[0]
	if r0.Name != "block-ssh" {
		t.Errorf("rule 0 name: expected 'block-ssh', got %q", r0.Name)
	}
	if len(r0.Patterns) != 1 || r0.Patterns[0] != "/home/user/.ssh/**" {
		t.Errorf("rule 0 patterns: %v", r0.Patterns)
	}
	if len(r0.Except) != 1 || r0.Except[0] != "/home/user/.ssh/config" {
		t.Errorf("rule 0 except: %v", r0.Except)
	}
	if len(r0.Operations) != 2 {
		t.Errorf("rule 0 operations: expected 2, got %d", len(r0.Operations))
	}

	// Verify second rule (block-evil network).
	r1 := policy.Rules[1]
	if r1.Name != "block-evil:network" {
		t.Errorf("rule 1 name: expected 'block-evil:network', got %q", r1.Name)
	}
	if len(r1.Hosts) != 2 {
		t.Errorf("rule 1 hosts: expected 2, got %d", len(r1.Hosts))
	}

	// Verify extra_ports and resources from config.
	if len(policy.ExtraPorts) != 1 {
		t.Errorf("expected 1 extra_ports entry, got %d", len(policy.ExtraPorts))
	}
	if policy.Resources == nil || policy.Resources.MemoryLimitMB == nil || *policy.Resources.MemoryLimitMB != 512 {
		t.Errorf("expected resources with MemoryLimitMB=512, got %+v", policy.Resources)
	}

	// Verify the policy marshals to valid JSON.
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("failed to marshal policy: %v", err)
	}
	if !json.Valid(data) {
		t.Fatal("policy JSON is not valid")
	}
}

func TestSandboxPlugin_Init(t *testing.T) {
	sp := &SandboxPlugin{binaryPath: "/usr/bin/bakelens-sandbox"}

	// Nil config should work.
	if err := sp.Init(nil); err != nil {
		t.Fatalf("Init(nil) error: %v", err)
	}

	// Valid config.
	cfg := json.RawMessage(`{"extra_ports":{"tcp":[80]},"resources":{"memory_limit_mb":256}}`)
	if err := sp.Init(cfg); err != nil {
		t.Fatalf("Init(valid) error: %v", err)
	}
	if sp.config.Resources == nil || sp.config.Resources.MemoryLimitMB == nil || *sp.config.Resources.MemoryLimitMB != 256 {
		t.Errorf("config not parsed: %+v", sp.config)
	}

	// Invalid JSON.
	bad := json.RawMessage(`{invalid}`)
	if err := sp.Init(bad); err == nil {
		t.Fatal("expected error for invalid config JSON")
	}

	// Invalid protocol.
	badProto := json.RawMessage(`{"extra_ports":{"http":[80]}}`)
	if err := sp.Init(badProto); err == nil {
		t.Fatal("expected error for invalid protocol")
	}

	// Invalid port range.
	badPort := json.RawMessage(`{"extra_ports":{"tcp":[0]}}`)
	if err := sp.Init(badPort); err == nil {
		t.Fatal("expected error for port 0")
	}

	// memory_limit_mb too low.
	badMem := json.RawMessage(`{"resources":{"memory_limit_mb":1}}`)
	if err := sp.Init(badMem); err == nil {
		t.Fatal("expected error for memory_limit_mb < 16")
	}

	// cpu_time_limit_secs too low.
	badCPU := json.RawMessage(`{"resources":{"cpu_time_limit_secs":0}}`)
	if err := sp.Init(badCPU); err == nil {
		t.Fatal("expected error for cpu_time_limit_secs < 1")
	}

	// max_processes too low.
	badProc := json.RawMessage(`{"resources":{"max_processes":0}}`)
	if err := sp.Init(badProc); err == nil {
		t.Fatal("expected error for max_processes < 1")
	}
}

func TestSandboxPlugin_Evaluate_BuildsPolicy(t *testing.T) {
	sp := &SandboxPlugin{binaryPath: "/usr/bin/bakelens-sandbox"}
	result := sp.Evaluate(context.Background(), Request{
		ToolName: "Bash",
		Command:  "ls -la",
		Rules: []RuleSnapshot{
			{
				Name:       "test",
				Enabled:    true,
				BlockPaths: []string{"/etc/**"},
			},
		},
	})
	if result != nil {
		t.Fatalf("expected nil (allow) for valid policy, got %+v", result)
	}
}

func TestSandboxPlugin_EmptyRules(t *testing.T) {
	sp := &SandboxPlugin{binaryPath: "/usr/bin/bakelens-sandbox"}
	policy := sp.BuildPolicy(Request{
		Command: "echo hello",
		Rules:   nil,
	})
	if policy.Rules == nil {
		t.Fatal("rules should be empty slice, not nil")
	}
	if len(policy.Rules) != 0 {
		t.Fatalf("expected 0 rules, got %d", len(policy.Rules))
	}
}

func TestSandboxPlugin_Available(t *testing.T) {
	sp := &SandboxPlugin{binaryPath: "/usr/bin/bakelens-sandbox"}
	if !sp.Available() {
		t.Fatal("expected Available() == true when binaryPath is set")
	}

	sp2 := &SandboxPlugin{}
	if sp2.Available() {
		t.Fatal("expected Available() == false when binaryPath is empty")
	}
}

func TestSandboxPlugin_ExecWithoutBinary(t *testing.T) {
	sp := &SandboxPlugin{} // no binary
	policy := sp.BuildPolicy(Request{Command: "echo hello"})
	_, err := sp.ExecPolicy(context.Background(), policy)
	if err == nil {
		t.Fatal("expected error when binary not available")
	}
}

func TestAbsolutePattern(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Already absolute — no change.
		{"/etc/shadow", "/etc/shadow"},
		{"/home/user/.ssh/**", "/home/user/.ssh/**"},
		{"~/Documents/**", "~/Documents/**"},

		// Relative ** patterns → prepend "/".
		{"**/.env", "/**/.env"},
		{"**/.env.*", "/**/.env.*"},
		{"**/.crust/**", "/**/.crust/**"},
		{"**/.git-credentials", "/**/.git-credentials"},
		{"**/.npmrc", "/**/.npmrc"},
		{"**/.vscode/settings.json", "/**/.vscode/settings.json"},
		{"**/.git/hooks/**", "/**/.git/hooks/**"},
		{"**/terraform.tfstate", "/**/terraform.tfstate"},
		{"**/.claude/settings*.json", "/**/.claude/settings*.json"},

		// Edge cases.
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := absolutePattern(tt.input)
			if got != tt.want {
				t.Errorf("absolutePattern(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestAbsolutePatterns_InBuildPolicy(t *testing.T) {
	sp := &SandboxPlugin{binaryPath: "/usr/bin/bakelens-sandbox"}
	policy := sp.BuildPolicy(Request{
		Command: "cat .env",
		Rules: []RuleSnapshot{{
			Name:        "protect-env",
			Enabled:     true,
			Actions:     []rules.Operation{rules.OpRead},
			BlockPaths:  []string{"**/.env", "**/.env.*", "/etc/shadow"},
			BlockExcept: []string{"**/.env.example"},
		}},
	})

	if len(policy.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(policy.Rules))
	}
	r := policy.Rules[0]

	wantPatterns := []string{"/**/.env", "/**/.env.*", "/etc/shadow"}
	for i, want := range wantPatterns {
		if r.Patterns[i] != want {
			t.Errorf("pattern[%d] = %q, want %q", i, r.Patterns[i], want)
		}
	}

	wantExcept := []string{"/**/.env.example"}
	for i, want := range wantExcept {
		if r.Except[i] != want {
			t.Errorf("except[%d] = %q, want %q", i, r.Except[i], want)
		}
	}
}

func TestResolveHosts_NameTruncation(t *testing.T) {
	longHost := strings.Repeat("a", 300)
	entries := resolveHosts(context.Background(), []string{longHost})
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if len(entries[0].Name) != maxHostName {
		t.Errorf("expected name truncated to %d, got %d", maxHostName, len(entries[0].Name))
	}
}

func TestBuildDenyRules_MaxRulesClamped(t *testing.T) {
	// Create 300 snapshots to exceed the 256 limit.
	snaps := make([]RuleSnapshot, 300)
	for i := range snaps {
		snaps[i] = RuleSnapshot{
			Name:       fmt.Sprintf("rule-%d", i),
			Enabled:    true,
			Actions:    []rules.Operation{rules.OpRead},
			BlockPaths: []string{fmt.Sprintf("/tmp/path%d", i)},
		}
	}
	result := buildDenyRules(context.Background(), snaps)
	if len(result) != maxRules {
		t.Errorf("expected %d rules (clamped), got %d", maxRules, len(result))
	}
}

func TestClampName_Truncation(t *testing.T) {
	seen := make(map[string]bool)
	long := strings.Repeat("x", 200)
	got := clampName(long, seen)
	if len(got) != maxRuleName {
		t.Errorf("expected name truncated to %d, got %d", maxRuleName, len(got))
	}
}

func TestClampName_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	n1 := clampName("my-rule", seen)
	n2 := clampName("my-rule", seen)
	if n1 == n2 {
		t.Errorf("expected unique names, both got %q", n1)
	}
	if n2 != "my-rule:2" {
		t.Errorf("expected 'my-rule:2', got %q", n2)
	}
}

func TestClampPatterns_DedupsAndCaps(t *testing.T) {
	// Duplicates should be removed.
	patterns := []string{"/a", "/b", "/a", "/c"}
	got := clampPatterns(patterns, 64)
	if len(got) != 3 {
		t.Errorf("expected 3 unique patterns, got %d: %v", len(got), got)
	}

	// Max count should be respected.
	many := make([]string, 100)
	for i := range many {
		many[i] = fmt.Sprintf("/path/%d", i)
	}
	got = clampPatterns(many, maxPatterns)
	if len(got) != maxPatterns {
		t.Errorf("expected %d patterns, got %d", maxPatterns, len(got))
	}

	// Long patterns should be truncated.
	longPat := "/" + strings.Repeat("x", 600)
	got = clampPatterns([]string{longPat}, 64)
	if len(got[0]) != maxPatternLen {
		t.Errorf("expected pattern truncated to %d, got %d", maxPatternLen, len(got[0]))
	}
}

func TestOperationsToStrings_Dedup(t *testing.T) {
	ops := []rules.Operation{rules.OpRead, rules.OpWrite, rules.OpRead}
	got := operationsToStrings(ops)
	if len(got) != 2 {
		t.Errorf("expected 2 unique ops, got %d: %v", len(got), got)
	}
}

func TestSandboxConfig_ValidateDuplicatePorts(t *testing.T) {
	sp := &SandboxPlugin{binaryPath: "/usr/bin/bakelens-sandbox"}
	cfg := json.RawMessage(`{"extra_ports":{"tcp":[80,80]}}`)
	if err := sp.Init(cfg); err == nil {
		t.Fatal("expected error for duplicate ports")
	}
}
