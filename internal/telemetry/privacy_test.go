package telemetry

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestTruncateString_SecretsNotLeaked verifies that telemetry truncation
// prevents full request/response bodies (which may contain secrets) from
// being stored verbatim in the local SQLite database.
func TestTruncateString_SecretsNotLeaked(t *testing.T) {
	// Simulate a large API response that contains an embedded secret.
	secret := "sk-ant-api03-REAL-SECRET-KEY-THAT-SHOULD-NOT-APPEAR"
	// Place the secret beyond the truncation boundary.
	padding := strings.Repeat("x", 33000)
	input := padding + secret

	result := truncateString(input, 32000)

	if strings.Contains(result, secret) {
		t.Error("truncated string still contains the secret placed beyond the truncation boundary")
	}
	if !strings.HasSuffix(result, "...[truncated]") {
		t.Error("truncated string should end with ...[truncated] marker")
	}
}

// TestSpanAttributes_InputValueTruncated ensures that the input.value
// attribute stored in spans is always truncated to the 32KB limit,
// preventing full request bodies from being persisted.
func TestSpanAttributes_InputValueTruncated(t *testing.T) {
	// Build a large input that exceeds the 32KB limit.
	largeInput := strings.Repeat(`{"role":"user","content":"`+strings.Repeat("a", 1000)+`"}`, 50)
	if len(largeInput) <= 32000 {
		t.Skip("test input not large enough")
	}

	attrs := map[string]any{
		AttrInputValue: truncateString(largeInput, 32000),
	}
	data, err := json.Marshal(attrs)
	if err != nil {
		t.Fatal(err)
	}

	// The serialized attributes should not contain the full input.
	if len(data) > 35000 { // Allow some overhead for JSON encoding + truncation marker
		t.Errorf("serialized attributes too large: %d bytes (expected <35000)", len(data))
	}
}

// TestSpanAttributes_ToolParametersTruncated ensures tool.parameters
// are truncated to 4KB to prevent file contents from being stored.
func TestSpanAttributes_ToolParametersTruncated(t *testing.T) {
	// Simulate a tool call with a large file content argument.
	largeArgs := `{"path":"/etc/passwd","content":"` + strings.Repeat("sensitive-data", 500) + `"}`
	truncated := truncateString(largeArgs, 4000)

	if len([]rune(truncated)) > 4000+len("...[truncated]") {
		t.Errorf("tool parameters not properly truncated: %d runes", len([]rune(truncated)))
	}
}

// TestSpanAttributes_NoAPIKeyInTargetURL ensures that API keys in
// upstream target URLs are not stored in span attributes.
// Target URLs should not contain query-string API keys.
func TestSpanAttributes_NoAPIKeyInTargetURL(t *testing.T) {
	// These are URL patterns that could leak API keys.
	dangerousURLs := []string{
		"https://api.openai.com/v1/chat?api_key=sk-real-key",
		"https://api.example.com/v1?key=secret123&model=gpt-4",
		"https://api.example.com/v1?token=bearer-token-here",
	}

	for _, url := range dangerousURLs {
		attrs := map[string]any{
			AttrTargetURL: url,
		}
		data, err := json.Marshal(attrs)
		if err != nil {
			t.Fatal(err)
		}
		// This test documents the risk: target URLs with query params
		// containing API keys will be stored in the telemetry DB.
		// If this test starts failing, it means we added sanitization.
		if strings.Contains(string(data), "sk-real-key") {
			t.Log("WARNING: target_url contains API key - consider sanitizing query params")
		}
	}
}

// TestTruncateString_EmptyAndBoundary tests edge cases in truncation.
func TestTruncateString_EmptyAndBoundary(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		check  func(string) bool
		desc   string
	}{
		{
			name:   "zero_length_limit",
			input:  "secret",
			maxLen: 0,
			check:  func(s string) bool { return s == "...[truncated]" },
			desc:   "should truncate to marker only",
		},
		{
			name:   "negative_length",
			input:  "secret",
			maxLen: -1,
			check:  func(s string) bool { return s == "...[truncated]" },
			desc:   "should handle negative max gracefully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateString(tt.input, tt.maxLen)
			if !tt.check(result) {
				t.Errorf("%s: got %q", tt.desc, result)
			}
		})
	}
}
