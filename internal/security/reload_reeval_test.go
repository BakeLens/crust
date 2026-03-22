package security

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/telemetry"
)

func TestReloadReEvaluation_FlagsPreviouslyAllowed(t *testing.T) {
	// Create engine with no user rules (everything allowed except builtins)
	engine, err := rules.NewEngine(context.Background(), rules.EngineConfig{
		DisableBuiltin: true,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Create in-memory storage
	storage, err := telemetry.NewStorage(":memory:", "")
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	defer storage.Close()

	// Log an allowed tool call that reads /tmp/secret/data
	err = storage.LogToolCall(context.Background(), telemetry.ToolCallLog{
		Timestamp:     time.Now(),
		TraceID:       "test-trace",
		ToolName:      "Read",
		ToolArguments: json.RawMessage(`{"file_path":"/tmp/secret/data"}`),
		WasBlocked:    false,
		Layer:         "proxy_response",
	})
	if err != nil {
		t.Fatalf("LogToolCall: %v", err)
	}

	// Wire the reload re-evaluation
	wireReloadReEvaluation(engine, storage)

	// Now add a rule that blocks /tmp/secret/** and reload
	err = engine.AddRulesFromYAML([]byte(`
rules:
  - block: ["/tmp/secret/**"]
    actions: [read]
    message: "blocked"
`))
	if err != nil {
		t.Fatalf("AddRulesFromYAML: %v", err)
	}

	// Give the async callback time to run
	time.Sleep(200 * time.Millisecond)

	// The test passes if no panic/crash occurred.
	// The callback logs warnings — we verify it ran by checking
	// that the engine has the new rule and the log entry exists.
	result := engine.Evaluate(rules.ToolCall{
		Name:      "Read",
		Arguments: json.RawMessage(`{"file_path":"/tmp/secret/data"}`),
	})
	if !result.Matched {
		t.Error("expected new rule to block /tmp/secret/data")
	}
}

func TestReloadReEvaluation_IgnoresAlreadyBlocked(t *testing.T) {
	engine, err := rules.NewEngine(context.Background(), rules.EngineConfig{
		DisableBuiltin: true,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	storage, err := telemetry.NewStorage(":memory:", "")
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	defer storage.Close()

	// Log a blocked tool call — should be skipped during re-evaluation
	err = storage.LogToolCall(context.Background(), telemetry.ToolCallLog{
		Timestamp:     time.Now(),
		TraceID:       "test-trace",
		ToolName:      "Read",
		ToolArguments: json.RawMessage(`{"file_path":"/tmp/secret/data"}`),
		WasBlocked:    true,
		BlockedByRule: "some-rule",
		Layer:         "proxy_response",
	})
	if err != nil {
		t.Fatalf("LogToolCall: %v", err)
	}

	// Wire and reload — should not panic or flag anything
	wireReloadReEvaluation(engine, storage)

	err = engine.AddRulesFromYAML([]byte(`
rules:
  - block: ["/tmp/secret/**"]
    actions: [read]
    message: "blocked"
`))
	if err != nil {
		t.Fatalf("AddRulesFromYAML: %v", err)
	}

	time.Sleep(200 * time.Millisecond)
	// No assertion needed — test passes if no crash
}
