package telemetry

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSanitizeSpan_StripsInputOutputValues(t *testing.T) {
	attrs := map[string]any{
		AttrInputValue:      "full request body with secrets",
		AttrOutputValue:     "full response body with PII",
		AttrToolParameters:  `{"path":"/etc/shadow"}`,
		AttrLLMModel:        "gpt-4",
		AttrLLMTokensInput:  100,
		AttrLLMTokensOutput: 200,
		AttrHTTPStatusCode:  200,
	}
	raw, _ := json.Marshal(attrs)

	span := Span{
		Name:       "test-span",
		SpanKind:   "LLM",
		Attributes: raw,
	}

	sanitized := SanitizeSpan(span)

	var result map[string]any
	if err := json.Unmarshal(sanitized.Attributes, &result); err != nil {
		t.Fatal(err)
	}

	// Sensitive keys must be removed.
	for _, key := range []string{AttrInputValue, AttrOutputValue, AttrToolParameters} {
		if _, ok := result[key]; ok {
			t.Errorf("sanitized span should not contain %q", key)
		}
	}

	// Safe metadata must be preserved.
	for _, key := range []string{AttrLLMModel, AttrLLMTokensInput, AttrLLMTokensOutput, AttrHTTPStatusCode} {
		if _, ok := result[key]; !ok {
			t.Errorf("sanitized span should preserve %q", key)
		}
	}
}

func TestSanitizeSpan_StripsTargetURLQueryParams(t *testing.T) {
	attrs := map[string]any{
		AttrTargetURL: "https://api.example.com/v1/chat?api_key=sk-secret-key&model=gpt-4",
		AttrLLMModel:  "gpt-4",
	}
	raw, _ := json.Marshal(attrs)

	span := Span{Attributes: raw}
	sanitized := SanitizeSpan(span)

	var result map[string]any
	if err := json.Unmarshal(sanitized.Attributes, &result); err != nil {
		t.Fatal(err)
	}

	url, ok := result[AttrTargetURL].(string)
	if !ok {
		t.Fatal("target_url should be a string")
	}
	if strings.Contains(url, "sk-secret-key") {
		t.Error("sanitized target URL should not contain API key")
	}
	if strings.Contains(url, "?") {
		t.Error("sanitized target URL should not contain query params")
	}
	if !strings.Contains(url, "api.example.com") {
		t.Error("sanitized target URL should preserve the host")
	}
}

func TestSanitizeToolCallLog_StripsArguments(t *testing.T) {
	log := ToolCallLog{
		ToolName:      "write_file",
		ToolArguments: json.RawMessage(`{"path":"/etc/passwd","content":"root:x:0:0..."}`),
		WasBlocked:    true,
		BlockedByRule: "block-etc",
	}

	sanitized := SanitizeToolCallLog(log)

	if sanitized.ToolArguments != nil {
		t.Error("tool_arguments should be nil after sanitization")
	}
	if sanitized.ToolName != "write_file" {
		t.Error("tool_name should be preserved")
	}
	if sanitized.BlockedByRule != "block-etc" {
		t.Error("blocked_by_rule should be preserved")
	}
}

func TestSanitizeToolCallLogs_Batch(t *testing.T) {
	logs := []ToolCallLog{
		{ToolName: "read_file", ToolArguments: json.RawMessage(`{"path":"/secret"}`)},
		{ToolName: "bash", ToolArguments: json.RawMessage(`{"cmd":"cat /etc/shadow"}`)},
		{ToolName: "list_dir", ToolArguments: nil}, // already nil
	}

	sanitized := SanitizeToolCallLogs(logs)

	if len(sanitized) != 3 {
		t.Fatalf("expected 3 logs, got %d", len(sanitized))
	}
	for i, l := range sanitized {
		if l.ToolArguments != nil {
			t.Errorf("log[%d] (%s): tool_arguments should be nil", i, l.ToolName)
		}
	}

	// Original should be unchanged (no mutation).
	if logs[0].ToolArguments == nil {
		t.Error("original log should not be mutated")
	}
}

func TestSanitizeTargetURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"no_query", "https://api.openai.com/v1/chat", "https://api.openai.com/v1/chat"},
		{"with_api_key", "https://api.example.com/v1?api_key=secret", "https://api.example.com/v1"},
		{"with_multiple_params", "https://api.example.com/v1?key=a&token=b&model=c", "https://api.example.com/v1"},
		{"invalid_url", "not-a-url", "not-a-url"},
		{"preserves_path", "https://api.openai.com/v1/chat/completions?key=x", "https://api.openai.com/v1/chat/completions"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeTargetURL(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeTargetURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestSanitizeSpan_MalformedJSON ensures graceful handling of corrupt data.
// Bug #15: previously returned raw unsanitized data on parse failure.
func TestSanitizeSpan_MalformedJSON(t *testing.T) {
	span := Span{Attributes: json.RawMessage(`{invalid json`)}
	sanitized := SanitizeSpan(span)
	// Unparseable attributes must be discarded to prevent leaking unsanitized data.
	if sanitized.Attributes != nil {
		t.Errorf("malformed attributes should be nil, got %q", string(sanitized.Attributes))
	}
}

// TestSanitizeAttributes_MalformedJSONWithSensitiveData verifies that
// malformed JSON containing sensitive data is discarded, not returned as-is.
func TestSanitizeAttributes_MalformedJSONWithSensitiveData(t *testing.T) {
	// This JSON is malformed but contains what looks like sensitive data.
	// sanitizeAttributes must NOT return it.
	malformed := json.RawMessage(`{"input.value": "secret password", INVALID`)
	result := sanitizeAttributes(malformed)
	if result != nil {
		t.Errorf("malformed JSON with sensitive data should return nil, got %q", string(result))
	}
}
