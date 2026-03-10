package plugin

import (
	"context"
	"encoding/json"
	"testing"
)

func TestStubPlugin_Name(t *testing.T) {
	sp := NewStubPlugin()
	if sp.Name() != "stub" {
		t.Fatalf("expected name 'stub', got %q", sp.Name())
	}
}

func TestStubPlugin_AllowByDefault(t *testing.T) {
	sp := NewStubPlugin()
	result := sp.Evaluate(context.Background(), Request{
		ToolName: "Bash",
		Command:  "ls -la",
	})
	if result != nil {
		t.Fatalf("expected nil (allow), got %+v", result)
	}
	if sp.CallCount() != 1 {
		t.Fatalf("expected 1 call, got %d", sp.CallCount())
	}
	if sp.Calls()[0].ToolName != "Bash" {
		t.Fatalf("expected tool 'Bash', got %q", sp.Calls()[0].ToolName)
	}
}

func TestStubPlugin_BlockConfigured(t *testing.T) {
	sp := NewStubPlugin()
	cfg := json.RawMessage(`{"block_tools":{"Bash":"no shell access"}}`)
	if err := sp.Init(cfg); err != nil {
		t.Fatalf("Init error: %v", err)
	}

	result := sp.Evaluate(context.Background(), Request{
		ToolName: "Bash",
		Command:  "rm -rf /",
	})
	if result == nil {
		t.Fatal("expected block result")
	}
	if result.RuleName != "stub:block-Bash" {
		t.Errorf("expected rule 'stub:block-Bash', got %q", result.RuleName)
	}
	if result.Message != "no shell access" {
		t.Errorf("expected message 'no shell access', got %q", result.Message)
	}
	if !sp.Calls()[0].Blocked {
		t.Error("expected call to be marked blocked")
	}
}

func TestStubPlugin_AllowUnblocked(t *testing.T) {
	sp := NewStubPlugin()
	cfg := json.RawMessage(`{"block_tools":{"Bash":"blocked"}}`)
	if err := sp.Init(cfg); err != nil {
		t.Fatalf("Init error: %v", err)
	}

	// Read is not blocked
	result := sp.Evaluate(context.Background(), Request{ToolName: "Read"})
	if result != nil {
		t.Fatalf("expected nil for Read, got %+v", result)
	}
}

func TestStubPlugin_InitNilConfig(t *testing.T) {
	sp := NewStubPlugin()
	if err := sp.Init(nil); err != nil {
		t.Fatalf("Init(nil) error: %v", err)
	}
}

func TestStubPlugin_InitInvalidJSON(t *testing.T) {
	sp := NewStubPlugin()
	if err := sp.Init(json.RawMessage(`{invalid}`)); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestStubPlugin_RegistryIntegration(t *testing.T) {
	pool := NewPool(0, 0)
	reg := NewRegistry(pool)

	sp := NewStubPlugin()
	cfg := json.RawMessage(`{"block_tools":{"Bash":"denied by stub"}}`)
	if err := reg.Register(sp, cfg); err != nil {
		t.Fatalf("Register error: %v", err)
	}

	// Evaluate via registry — should block Bash
	result := reg.Evaluate(context.Background(), Request{
		ToolName: "Bash",
		Command:  "echo hello",
	})
	if result == nil {
		t.Fatal("expected block result from registry")
	}
	if result.RuleName != "stub:block-Bash" {
		t.Errorf("expected rule 'stub:block-Bash', got %q", result.RuleName)
	}

	// Read should be allowed
	result = reg.Evaluate(context.Background(), Request{ToolName: "Read"})
	if result != nil {
		t.Fatalf("expected nil for Read, got %+v", result)
	}

	// Verify call recording
	if sp.CallCount() != 2 {
		t.Fatalf("expected 2 calls, got %d", sp.CallCount())
	}
}
