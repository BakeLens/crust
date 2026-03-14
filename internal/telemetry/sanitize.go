package telemetry

import (
	"encoding/json"
	"net/url"
	"strings"
)

// =============================================================================
// Privacy Sanitization Layer
// =============================================================================
//
// All data returned by management API endpoints MUST pass through these
// sanitizers before being sent to clients. Raw data remains in the local
// SQLite database for forensic inspection (via sqlite3 CLI).
//
// Threat model:
//   - Local processes querying the management API
//   - Screen display (TUI shoulder surfing)
//   - API responses accidentally included in bug reports or logs
//
// What gets sanitized:
//   - Span attributes: input.value, output.value (full LLM messages)
//   - Span attributes: tool.parameters (tool call arguments)
//   - Span attributes: http.target_url (query params may contain keys)
//   - ToolCallLog: tool_arguments (file contents, secrets, commands)

// sensitiveAttrKeys lists span attribute keys that contain privacy-sensitive
// data and must be stripped from API responses.
var sensitiveAttrKeys = []string{
	AttrInputValue,     // "input.value" — full LLM request messages
	AttrOutputValue,    // "output.value" — full LLM response body
	AttrToolParameters, // "tool.parameters" — tool call arguments
}

// SanitizeSpan returns a copy of the span with sensitive attributes removed.
// Safe metadata (model, tokens, latency, status) is preserved.
func SanitizeSpan(s Span) Span {
	s.Attributes = sanitizeAttributes(s.Attributes)
	return s
}

// SanitizeSpans returns sanitized copies of all spans.
func SanitizeSpans(spans []Span) []Span {
	out := make([]Span, len(spans))
	for i, s := range spans {
		out[i] = SanitizeSpan(s)
	}
	return out
}

// SanitizeToolCallLog returns a copy with tool_arguments redacted.
func SanitizeToolCallLog(l ToolCallLog) ToolCallLog {
	l.ToolArguments = nil
	return l
}

// SanitizeToolCallLogs returns sanitized copies of all logs.
func SanitizeToolCallLogs(logs []ToolCallLog) []ToolCallLog {
	out := make([]ToolCallLog, len(logs))
	for i, l := range logs {
		out[i] = SanitizeToolCallLog(l)
	}
	return out
}

// SanitizeTargetURL strips query parameters from a URL to prevent
// API keys or tokens passed as query params from being stored.
// Called at recording time (not just API response time) because
// URLs with embedded keys should never hit the database.
func SanitizeTargetURL(rawURL string) string {
	if rawURL == "" {
		return rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if u.RawQuery == "" {
		return rawURL
	}
	// Strip all query parameters — they may contain api_key, token, key, etc.
	u.RawQuery = ""
	u.ForceQuery = false
	return u.String()
}

// sanitizeAttributes parses span attributes JSON, removes sensitive keys,
// sanitizes target URLs, and re-marshals.
func sanitizeAttributes(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}

	var attrs map[string]any
	if err := json.Unmarshal(raw, &attrs); err != nil {
		return nil // unparseable — discard to avoid leaking unsanitized data
	}

	changed := false
	for _, key := range sensitiveAttrKeys {
		if _, ok := attrs[key]; ok {
			delete(attrs, key)
			changed = true
		}
	}

	// Sanitize target URL query params.
	if targetURL, ok := attrs[AttrTargetURL]; ok {
		if s, ok := targetURL.(string); ok && strings.Contains(s, "?") {
			attrs[AttrTargetURL] = SanitizeTargetURL(s)
			changed = true
		}
	}

	if !changed {
		return raw
	}

	out, err := json.Marshal(attrs)
	if err != nil {
		return raw
	}
	return out
}
