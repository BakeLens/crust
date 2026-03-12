//go:build libcrust

package libcrust

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestInitAndEvaluate(t *testing.T) {
	if err := Init(""); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Shutdown()

	if n := RuleCount(); n == 0 {
		t.Fatal("expected builtin rules to be loaded")
	}

	// Allowed tool call — reading a temp file
	result := Evaluate("read_file", `{"path":"/tmp/test.txt"}`)
	var m map[string]any
	if err := json.Unmarshal([]byte(result), &m); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if m["matched"] == true {
		t.Errorf("expected /tmp/test.txt to be allowed, got: %s", result)
	}

	// Blocked tool call — writing to /etc/crontab (builtin protect-persistence)
	result = Evaluate("write_file", `{"file_path":"/etc/crontab","content":"* * * * * evil"}`)
	if err := json.Unmarshal([]byte(result), &m); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if m["matched"] != true {
		t.Errorf("expected /etc/crontab write to be blocked, got: %s", result)
	}
}

func TestInitWithYAML(t *testing.T) {
	yaml := `
rules:
  - name: block-secrets
    message: Secret file access blocked
    actions: [read, write]
    block: "/etc/shadow"
`
	if err := InitWithYAML(yaml); err != nil {
		t.Fatalf("InitWithYAML failed: %v", err)
	}
	defer Shutdown()

	if n := RuleCount(); n == 0 {
		t.Fatal("expected rules to be loaded")
	}

	// Verify custom rule blocks /etc/shadow
	result := Evaluate("read_file", `{"path":"/etc/shadow"}`)
	var m map[string]any
	if err := json.Unmarshal([]byte(result), &m); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if m["matched"] != true {
		t.Errorf("expected /etc/shadow to be blocked, got: %s", result)
	}
}

func TestInterceptResponse(t *testing.T) {
	if err := Init(""); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Shutdown()

	// Simple Anthropic response with a benign tool call
	body := `{"content":[{"type":"tool_use","id":"t1","name":"read_file","input":{"path":"/tmp/test.txt"}}]}`
	result := InterceptResponse(body, "anthropic", "remove")
	if !strings.Contains(result, "read_file") {
		t.Errorf("expected allowed tool call in output: %s", result)
	}
}

func TestEvaluateBeforeInit(t *testing.T) {
	Shutdown() // ensure clean state
	result := Evaluate("test", `{}`)
	if !strings.Contains(result, "not initialized") {
		t.Errorf("expected not-initialized error, got: %s", result)
	}
}

func TestValidateYAML(t *testing.T) {
	if err := Init(""); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Shutdown()

	// Valid YAML
	valid := `
rules:
  - name: test-rule
    message: test
    actions: [read, write]
    block: "/secret/**"
`
	if msg := ValidateYAML(valid); msg != "" {
		t.Errorf("expected valid, got: %s", msg)
	}

	// Invalid YAML
	invalid := `not: valid: yaml: [`
	if msg := ValidateYAML(invalid); msg == "" {
		t.Error("expected error for invalid YAML")
	}
}

func TestGetVersion(t *testing.T) {
	v := GetVersion()
	if v == "" {
		t.Error("expected non-empty version")
	}
}
