package plugin

import (
	"context"
	"encoding/json"
	"os/exec"
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
			Resources:  &ResourcePolicy{MaxMemoryMB: 512},
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
	if policy.Resources == nil || policy.Resources.MaxMemoryMB != 512 {
		t.Errorf("expected resources with MaxMemoryMB=512, got %+v", policy.Resources)
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
	cfg := json.RawMessage(`{"extra_ports":{"tcp":[80]},"resources":{"max_memory_mb":256}}`)
	if err := sp.Init(cfg); err != nil {
		t.Fatalf("Init(valid) error: %v", err)
	}
	if sp.config.Resources == nil || sp.config.Resources.MaxMemoryMB != 256 {
		t.Errorf("config not parsed: %+v", sp.config)
	}

	// Invalid config.
	bad := json.RawMessage(`{invalid}`)
	if err := sp.Init(bad); err == nil {
		t.Fatal("expected error for invalid config JSON")
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
