package telemetry

import (
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

// TestSpanAttributes_NoAPIKeyInTargetURL ensures that API keys in
// upstream target URLs are sanitized before storage.
func TestSpanAttributes_NoAPIKeyInTargetURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		key  string
	}{
		{"openai_api_key", "https://api.openai.com/v1/chat?api_key=sk-real-key", "sk-real-key"},
		{"generic_key_param", "https://api.example.com/v1?key=secret123&model=gpt-4", "secret123"},
		{"token_param", "https://api.example.com/v1?token=bearer-token-here", "bearer-token-here"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sanitized := SanitizeTargetURL(tt.url)
			if strings.Contains(sanitized, tt.key) {
				t.Errorf("SanitizeTargetURL(%q) still contains key %q", tt.url, tt.key)
			}
		})
	}
}
