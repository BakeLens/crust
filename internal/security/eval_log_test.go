package security

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/BakeLens/crust/internal/rules"
)

func TestEvalLog_RecordAndQuery(t *testing.T) {
	log := NewEvalLog(10)

	// Record some evaluations
	log.Record(rules.ToolCall{Name: "Read", Arguments: json.RawMessage(`{"file_path":"/tmp/a"}`)}, false)
	log.Record(rules.ToolCall{Name: "Bash", Arguments: json.RawMessage(`{"command":"ls"}`)}, false)
	log.Record(rules.ToolCall{Name: "Write", Arguments: json.RawMessage(`{"file_path":"/etc/passwd"}`)}, true)

	logs, err := log.GetRecentLogs(context.Background(), 5, 100)
	if err != nil {
		t.Fatalf("GetRecentLogs: %v", err)
	}
	if len(logs) != 3 {
		t.Fatalf("expected 3 logs, got %d", len(logs))
	}
	// Newest first
	if logs[0].ToolName != "Write" {
		t.Errorf("expected newest first (Write), got %s", logs[0].ToolName)
	}
	if !logs[0].WasBlocked {
		t.Error("Write should be marked as blocked")
	}
	if logs[2].ToolName != "Read" {
		t.Errorf("expected oldest last (Read), got %s", logs[2].ToolName)
	}
}

func TestEvalLog_RingBufferWraps(t *testing.T) {
	log := NewEvalLog(3)

	// Fill beyond capacity
	log.Record(rules.ToolCall{Name: "a"}, false)
	log.Record(rules.ToolCall{Name: "b"}, false)
	log.Record(rules.ToolCall{Name: "c"}, false)
	log.Record(rules.ToolCall{Name: "d"}, false) // overwrites "a"

	logs, _ := log.GetRecentLogs(context.Background(), 5, 100)
	if len(logs) != 3 {
		t.Fatalf("expected 3 logs after wrap, got %d", len(logs))
	}
	// Should have d, c, b (newest first), "a" was overwritten
	if logs[0].ToolName != "d" {
		t.Errorf("expected d, got %s", logs[0].ToolName)
	}
	if logs[2].ToolName != "b" {
		t.Errorf("expected b, got %s", logs[2].ToolName)
	}
}

func TestEvalLog_Limit(t *testing.T) {
	log := NewEvalLog(100)
	for range 50 {
		log.Record(rules.ToolCall{Name: "tool"}, false)
	}

	logs, _ := log.GetRecentLogs(context.Background(), 5, 10)
	if len(logs) != 10 {
		t.Errorf("expected limit of 10, got %d", len(logs))
	}
}

func TestEvalLog_ReloadReEval_WithEvalLog(t *testing.T) {
	// Integration: EvalLog as RecentLogQuerier for WireReloadReEvaluation
	engine, err := rules.NewEngine(context.Background(), rules.EngineConfig{DisableBuiltin: true})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	evalLog := NewEvalLog(100)

	// Record an allowed tool call
	evalLog.Record(rules.ToolCall{
		Name:      "Read",
		Arguments: json.RawMessage(`{"file_path":"/tmp/secret/data"}`),
	}, false)

	// Wire reload re-evaluation with EvalLog
	WireReloadReEvaluation(engine, evalLog)

	// Add a rule that blocks /tmp/secret/**
	err = engine.AddRulesFromYAML([]byte(`
rules:
  - block: ["/tmp/secret/**"]
    actions: [read]
    message: "blocked"
`))
	if err != nil {
		t.Fatalf("AddRulesFromYAML: %v", err)
	}

	// Give async callback time to run
	// (test passes if no panic — callback logs warnings)
	time.Sleep(200 * time.Millisecond)
}
