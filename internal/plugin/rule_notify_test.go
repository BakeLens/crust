package plugin

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/BakeLens/crust/internal/rules"
)

// TestPlugin_RulesSnapshotUpdatesOnAdd verifies that after a rule is added,
// the plugin receives the updated rules snapshot in the next Evaluate call.
func TestPlugin_RulesSnapshotUpdatesOnAdd(t *testing.T) {
	var captured []RuleSnapshot

	// A spy plugin that records the rules it receives.
	spy := &spyPlugin{
		name: "rule-spy",
		evalFn: func(_ context.Context, req Request) *Result {
			captured = req.Rules
			return nil // allow
		},
	}

	pool := NewPool(1, 0)
	reg := NewRegistry(pool)
	if err := reg.Register(spy, nil); err != nil {
		t.Fatalf("register: %v", err)
	}
	defer reg.Close()

	// Evaluate with no rules.
	reg.Evaluate(context.Background(), Request{
		ToolName: "Bash",
		Command:  "echo hello",
		Rules:    nil,
	})
	if len(captured) != 0 {
		t.Errorf("expected 0 rules before add, got %d", len(captured))
	}

	// Simulate adding a rule: pass updated snapshot.
	reg.Evaluate(context.Background(), Request{
		ToolName: "Bash",
		Command:  "echo hello",
		Rules: []RuleSnapshot{
			{
				Name:       "protect-ssh-keys",
				Enabled:    true,
				BlockPaths: []string{"$HOME/.ssh/id_*"},
				Actions:    []rules.Operation{rules.OpRead, rules.OpWrite},
				Locked:     true,
			},
		},
	})
	if len(captured) != 1 {
		t.Fatalf("expected 1 rule after add, got %d", len(captured))
	}
	if captured[0].Name != "protect-ssh-keys" {
		t.Errorf("rule name = %q, want %q", captured[0].Name, "protect-ssh-keys")
	}
}

// TestPlugin_RulesSnapshotUpdatesOnRemove verifies that after a rule is removed,
// the plugin no longer sees it in the next Evaluate call.
func TestPlugin_RulesSnapshotUpdatesOnRemove(t *testing.T) {
	var captured []RuleSnapshot

	spy := &spyPlugin{
		name: "rule-spy",
		evalFn: func(_ context.Context, req Request) *Result {
			captured = req.Rules
			return nil
		},
	}

	pool := NewPool(1, 0)
	reg := NewRegistry(pool)
	if err := reg.Register(spy, nil); err != nil {
		t.Fatalf("register: %v", err)
	}
	defer reg.Close()

	twoRules := []RuleSnapshot{
		{Name: "protect-ssh-keys", Enabled: true, BlockPaths: []string{"$HOME/.ssh/id_*"}},
		{Name: "protect-env-files", Enabled: true, BlockPaths: []string{"**/.env"}},
	}

	// Evaluate with two rules.
	reg.Evaluate(context.Background(), Request{
		ToolName: "Bash",
		Command:  "echo hello",
		Rules:    twoRules,
	})
	if len(captured) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(captured))
	}

	// Simulate removing one rule.
	reg.Evaluate(context.Background(), Request{
		ToolName: "Bash",
		Command:  "echo hello",
		Rules:    twoRules[:1], // only protect-ssh-keys remains
	})
	if len(captured) != 1 {
		t.Fatalf("expected 1 rule after remove, got %d", len(captured))
	}
	if captured[0].Name != "protect-ssh-keys" {
		t.Errorf("remaining rule = %q, want %q", captured[0].Name, "protect-ssh-keys")
	}
}

// TestPlugin_LockedRulesAlwaysPresent verifies that locked builtin rules
// cannot be removed from the snapshot (they survive --disable-builtin).
func TestPlugin_LockedRulesAlwaysPresent(t *testing.T) {
	var captured []RuleSnapshot

	spy := &spyPlugin{
		name: "rule-spy",
		evalFn: func(_ context.Context, req Request) *Result {
			captured = req.Rules
			return nil
		},
	}

	pool := NewPool(1, 0)
	reg := NewRegistry(pool)
	if err := reg.Register(spy, nil); err != nil {
		t.Fatalf("register: %v", err)
	}
	defer reg.Close()

	// Simulate: only locked builtin rules remain after --disable-builtin.
	reg.Evaluate(context.Background(), Request{
		ToolName: "Bash",
		Command:  "cat /etc/shadow",
		Rules: []RuleSnapshot{
			{Name: "protect-system-auth", Enabled: true, Locked: true, BlockPaths: []string{"/etc/shadow"}},
			{Name: "protect-ssh-keys", Enabled: true, Locked: true, BlockPaths: []string{"$HOME/.ssh/id_*"}},
		},
	})
	if len(captured) != 2 {
		t.Fatalf("expected 2 locked rules, got %d", len(captured))
	}
	for _, r := range captured {
		if !r.Locked {
			t.Errorf("rule %q should be locked", r.Name)
		}
	}
}

// TestSandboxPlugin_PolicyChangesWithRules verifies that the sandbox plugin
// builds different policies when rules are added or removed.
func TestSandboxPlugin_PolicyChangesWithRules(t *testing.T) {
	sp := &SandboxPlugin{binaryPath: "/usr/bin/bakelens-sandbox"}

	// Policy with one rule.
	p1 := sp.BuildPolicy(Request{
		Command: "cat /etc/shadow",
		Rules: []RuleSnapshot{
			{Name: "protect-system-auth", Enabled: true, Actions: []rules.Operation{rules.OpRead}, BlockPaths: []string{"/etc/shadow"}},
		},
	})
	if len(p1.Rules) != 1 {
		t.Fatalf("expected 1 deny rule, got %d", len(p1.Rules))
	}

	// Policy after adding a second rule.
	p2 := sp.BuildPolicy(Request{
		Command: "cat /etc/shadow",
		Rules: []RuleSnapshot{
			{Name: "protect-system-auth", Enabled: true, Actions: []rules.Operation{rules.OpRead}, BlockPaths: []string{"/etc/shadow"}},
			{Name: "protect-ssh-keys", Enabled: true, Actions: []rules.Operation{rules.OpRead}, BlockPaths: []string{"/home/user/.ssh/id_*"}},
		},
	})
	if len(p2.Rules) != 2 {
		t.Fatalf("expected 2 deny rules after add, got %d", len(p2.Rules))
	}

	// Policy after removing the first rule.
	p3 := sp.BuildPolicy(Request{
		Command: "cat /etc/shadow",
		Rules: []RuleSnapshot{
			{Name: "protect-ssh-keys", Enabled: true, Actions: []rules.Operation{rules.OpRead}, BlockPaths: []string{"/home/user/.ssh/id_*"}},
		},
	})
	if len(p3.Rules) != 1 {
		t.Fatalf("expected 1 deny rule after remove, got %d", len(p3.Rules))
	}
	if p3.Rules[0].Name != "protect-ssh-keys" {
		t.Errorf("remaining rule = %q, want %q", p3.Rules[0].Name, "protect-ssh-keys")
	}
}

// TestSandboxPlugin_DisabledRulesExcluded verifies that disabled rules
// are not included in the sandbox policy.
func TestSandboxPlugin_DisabledRulesExcluded(t *testing.T) {
	sp := &SandboxPlugin{binaryPath: "/usr/bin/bakelens-sandbox"}

	policy := sp.BuildPolicy(Request{
		Command: "echo test",
		Rules: []RuleSnapshot{
			{Name: "active-rule", Enabled: true, Actions: []rules.Operation{rules.OpRead}, BlockPaths: []string{"/tmp/secret"}},
			{Name: "disabled-rule", Enabled: false, Actions: []rules.Operation{rules.OpRead}, BlockPaths: []string{"/tmp/other"}},
		},
	})
	if len(policy.Rules) != 1 {
		t.Fatalf("expected 1 rule (disabled excluded), got %d", len(policy.Rules))
	}
	if policy.Rules[0].Name != "active-rule" {
		t.Errorf("rule name = %q, want %q", policy.Rules[0].Name, "active-rule")
	}
}

// spyPlugin records what it receives for test assertions.
type spyPlugin struct {
	name   string
	evalFn func(context.Context, Request) *Result
}

func (s *spyPlugin) Name() string                                      { return s.name }
func (s *spyPlugin) Init(_ json.RawMessage) error                      { return nil }
func (s *spyPlugin) Evaluate(ctx context.Context, req Request) *Result { return s.evalFn(ctx, req) }
func (s *spyPlugin) Close() error                                      { return nil }
