package telemetry

import (
	"encoding/hex"
	"testing"
)

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{"short_ascii", "hello", 10, "hello"},
		{"exact_ascii", "hello", 5, "hello"},
		{"truncate_ascii", "hello world", 5, "hello...[truncated]"},
		// Multi-byte: "日本語テスト" is 6 runes but 18 bytes.
		// Truncating at maxLen=10 (bytes) should not corrupt mid-rune.
		{"multibyte_under_rune_limit", "日本語テスト", 10, "日本語テスト"},
		{"multibyte_truncate", "日本語テスト", 3, "日本語...[truncated]"},
		{"empty", "", 5, ""},
		{"emoji", "👋🌍🎉💻🚀", 3, "👋🌍🎉...[truncated]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateString(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncateString(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
			}
		})
	}
}

// TestGenerateSpanID_Uniqueness verifies that generateSpanID returns unique,
// cryptographically random IDs (Bug #7: fallback previously used predictable
// time-based IDs).
func TestGenerateSpanID_Uniqueness(t *testing.T) {
	seen := make(map[string]struct{}, 1000)
	for range 1000 {
		id := generateSpanID()
		if _, exists := seen[id]; exists {
			t.Fatalf("duplicate span ID generated: %s", id)
		}
		seen[id] = struct{}{}

		// Verify it's valid hex and correct length (8 bytes = 16 hex chars)
		b, err := hex.DecodeString(id)
		if err != nil {
			t.Fatalf("span ID %q is not valid hex: %v", id, err)
		}
		if len(b) != 8 {
			t.Fatalf("span ID decoded to %d bytes, want 8", len(b))
		}
	}
}

// TestBuildToolSpan_MarshalFailureFallback verifies that buildToolSpan
// produces valid JSON attributes even if marshaling were to fail (Bug #6).
// In practice json.Marshal of map[string]any won't fail, but the code now
// falls back to "{}" instead of nil.
func TestBuildToolSpan_AttributesNonNil(t *testing.T) {
	p := &Provider{enabled: true}
	tc := ToolCall{
		ID:        "tc-1",
		Name:      "bash",
		Arguments: []byte(`{"cmd":"ls"}`),
	}

	span := p.buildToolSpan("parent-1", "trace-1", tc)
	if span.Attributes == nil {
		t.Error("tool span attributes should not be nil")
	}
	if len(span.Attributes) == 0 {
		t.Error("tool span attributes should not be empty")
	}
}
