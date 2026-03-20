//go:build libcrust

package libcrust

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestLibcrustE2E exercises the libcrust public API end-to-end.
// Tests use global state and must not run in parallel.
func TestLibcrustE2E(t *testing.T) {
	t.Run("InitAndEvaluate", func(t *testing.T) {
		if err := Init(""); err != nil {
			t.Fatalf("Init failed: %v", err)
		}
		t.Cleanup(Shutdown)

		if n := RuleCount(); n <= 0 {
			t.Fatalf("expected RuleCount > 0, got %d", n)
		}

		// .env file should be blocked by builtin rules.
		res := Evaluate("Read", `{"file_path":"/app/.env"}`)
		var m map[string]any
		if err := json.Unmarshal([]byte(res), &m); err != nil {
			t.Fatalf("bad JSON: %v", err)
		}
		if m["matched"] != true {
			t.Errorf("expected /app/.env to be blocked, got: %s", res)
		}

		// Safe file should be allowed.
		res = Evaluate("Read", `{"file_path":"/tmp/safe.txt"}`)
		if err := json.Unmarshal([]byte(res), &m); err != nil {
			t.Fatalf("bad JSON: %v", err)
		}
		if m["matched"] == true {
			t.Errorf("expected /tmp/safe.txt to be allowed, got: %s", res)
		}
	})

	t.Run("InitWithYAML_CustomRuleBlocks", func(t *testing.T) {
		yaml := `
rules:
  - name: block-secret-dir
    message: Secret directory access blocked
    actions: [read, write]
    block: "/secret/**"
`
		if err := InitWithYAML(yaml); err != nil {
			t.Fatalf("InitWithYAML failed: %v", err)
		}
		t.Cleanup(Shutdown)

		res := Evaluate("Read", `{"file_path":"/secret/data.txt"}`)
		var m map[string]any
		if err := json.Unmarshal([]byte(res), &m); err != nil {
			t.Fatalf("bad JSON: %v", err)
		}
		if m["matched"] != true {
			t.Errorf("expected /secret/data.txt to be blocked, got: %s", res)
		}

		res = Evaluate("Read", `{"file_path":"/tmp/ok.txt"}`)
		if err := json.Unmarshal([]byte(res), &m); err != nil {
			t.Fatalf("bad JSON: %v", err)
		}
		if m["matched"] == true {
			t.Errorf("expected /tmp/ok.txt to be allowed, got: %s", res)
		}
	})

	t.Run("AddRulesYAML_AfterInit", func(t *testing.T) {
		if err := Init(""); err != nil {
			t.Fatalf("Init failed: %v", err)
		}
		t.Cleanup(Shutdown)

		initial := RuleCount()

		yaml := `
rules:
  - name: e2e-added-rule
    message: Added rule blocks /e2e-blocked/**
    actions: [read, write]
    block: "/e2e-blocked/**"
`
		if err := AddRulesYAML(yaml); err != nil {
			t.Fatalf("AddRulesYAML failed: %v", err)
		}

		after := RuleCount()
		if after <= initial {
			t.Errorf("expected RuleCount to increase: %d -> %d", initial, after)
		}

		res := Evaluate("Read", `{"file_path":"/e2e-blocked/secret.txt"}`)
		var m map[string]any
		if err := json.Unmarshal([]byte(res), &m); err != nil {
			t.Fatalf("bad JSON: %v", err)
		}
		if m["matched"] != true {
			t.Errorf("expected /e2e-blocked/secret.txt to be blocked, got: %s", res)
		}
	})

	t.Run("InterceptResponse_BlocksToolCall", func(t *testing.T) {
		if err := Init(""); err != nil {
			t.Fatalf("Init failed: %v", err)
		}
		t.Cleanup(Shutdown)

		// Anthropic-format response with a tool_use reading .env
		body := `{"content":[{"type":"tool_use","id":"t1","name":"Read","input":{"file_path":"/app/.env"}}]}`
		res := InterceptResponse(body, "anthropic", "remove")

		var result map[string]any
		if err := json.Unmarshal([]byte(res), &result); err != nil {
			t.Fatalf("bad JSON: %v", err)
		}

		blocked, ok := result["blocked"].([]any)
		if !ok {
			t.Fatalf("expected blocked array, got: %s", res)
		}
		if len(blocked) != 1 {
			t.Errorf("expected 1 blocked entry, got %d: %s", len(blocked), res)
		}
	})

	t.Run("GetPluginStats_AfterInit", func(t *testing.T) {
		if err := Init(""); err != nil {
			t.Fatalf("Init failed: %v", err)
		}
		t.Cleanup(Shutdown)

		stats := GetPluginStats()
		// Should be valid JSON (either [] or an array of stats).
		var parsed any
		if err := json.Unmarshal([]byte(stats), &parsed); err != nil {
			t.Fatalf("GetPluginStats returned invalid JSON: %v — got: %s", err, stats)
		}
	})

	t.Run("ValidateYAML_Valid", func(t *testing.T) {
		if err := Init(""); err != nil {
			t.Fatalf("Init failed: %v", err)
		}
		t.Cleanup(Shutdown)

		valid := `
rules:
  - name: valid-rule
    message: A valid rule
    actions: [read]
    block: "/foo/**"
`
		if msg := ValidateYAML(valid); msg != "" {
			t.Errorf("expected empty string for valid YAML, got: %s", msg)
		}
	})

	t.Run("ValidateYAML_Invalid", func(t *testing.T) {
		if err := Init(""); err != nil {
			t.Fatalf("Init failed: %v", err)
		}
		t.Cleanup(Shutdown)

		invalid := `not: valid: yaml: [`
		if msg := ValidateYAML(invalid); msg == "" {
			t.Error("expected non-empty error string for invalid YAML")
		}
	})

	t.Run("ScanContent_DetectsSecret", func(t *testing.T) {
		if err := Init(""); err != nil {
			t.Fatalf("Init failed: %v", err)
		}
		t.Cleanup(Shutdown)

		// Construct a fake Heroku API key at runtime to match builtin:dlp-heroku-api-key
		// pattern (heroku_<uuid>) without triggering source-level DLP.
		fakeKey := "heroku_" + "deadbeef-dead-beef-dead-beefdeadbeef"
		content := "my config: API_KEY=" + fakeKey
		res := ScanContent(content)

		var m map[string]any
		if err := json.Unmarshal([]byte(res), &m); err != nil {
			t.Fatalf("bad JSON: %v", err)
		}
		if m["matched"] != true {
			t.Errorf("expected DLP to detect heroku key pattern, got: %s", res)
		}
	})

	t.Run("ValidateURL_BlocksTel", func(t *testing.T) {
		if err := Init(""); err != nil {
			t.Fatalf("Init failed: %v", err)
		}
		t.Cleanup(Shutdown)

		// tel: scheme should be blocked.
		res := ValidateURL("tel:+1234567890")
		var m map[string]any
		if err := json.Unmarshal([]byte(res), &m); err != nil {
			t.Fatalf("bad JSON: %v", err)
		}
		if m["blocked"] != true {
			t.Errorf("expected tel: to be blocked, got: %s", res)
		}

		// https: should be allowed.
		res = ValidateURL("https://example.com")
		if err := json.Unmarshal([]byte(res), &m); err != nil {
			t.Fatalf("bad JSON: %v", err)
		}
		if m["blocked"] == true {
			t.Errorf("expected https: to be allowed, got: %s", res)
		}
	})

	t.Run("Evaluate_BeforeInit_ReturnsError", func(t *testing.T) {
		Shutdown() // ensure not initialized

		res := Evaluate("Read", `{"file_path":"/tmp/test.txt"}`)
		var m map[string]any
		if err := json.Unmarshal([]byte(res), &m); err != nil {
			t.Fatalf("bad JSON: %v", err)
		}
		if _, hasError := m["error"]; !hasError {
			t.Errorf("expected error field in result, got: %s", res)
		}
		if !strings.Contains(res, "not initialized") {
			t.Errorf("expected 'not initialized' error, got: %s", res)
		}
	})
}
