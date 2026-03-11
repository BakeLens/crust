package security

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/BakeLens/crust/internal/eventlog"
	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/selfprotect"
	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/types"
)

// --- Full Pipeline E2E Tests ---
//
// These tests exercise the complete security pipeline end-to-end:
//   selfprotect (Step 0) → rules engine (13-step) → interceptor → telemetry → privacy sanitization

// newE2EInterceptor creates an interceptor with builtin rules + selfprotect
// pre-checker — the same configuration used in production.
func newE2EInterceptor(t *testing.T) *Interceptor {
	t.Helper()
	rulesDir := setupTestRulesDir(t, "")
	engine, err := rules.NewEngine(context.Background(), rules.EngineConfig{
		UserRulesDir:   rulesDir,
		DisableBuiltin: false,
		PreChecker:     selfprotect.Check,
	})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	storage, err := telemetry.NewStorage(":memory:", "")
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	t.Cleanup(func() { storage.Close() })
	return NewInterceptor(engine, storage)
}

// e2eCtx returns an Anthropic InterceptionContext for e2e tests.
func e2eCtx(name string) InterceptionContext {
	return InterceptionContext{
		TraceID:   types.TraceID("trace-" + name),
		SessionID: types.SessionID("session-" + name),
		Model:     "claude-3-opus",
		APIType:   types.APITypeAnthropic,
		BlockMode: types.BlockModeRemove,
	}
}

// e2eIntercept is a shorthand: reset metrics, create interceptor, run interception.
func e2eIntercept(t *testing.T, response []byte, ctx InterceptionContext) *InterceptionResult {
	t.Helper()
	eventlog.GetMetrics().Reset()
	interceptor := newE2EInterceptor(t)
	result, err := interceptor.InterceptToolCalls(response, ctx)
	if err != nil {
		t.Fatalf("InterceptToolCalls: %v", err)
	}
	return result
}

func mustMarshal(t *testing.T, v any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("mustMarshal: %v", err)
	}
	return data
}

// TestE2E_FullPipeline_BlocksCredentialAccess tests the complete pipeline:
// LLM response with tool call reading .env → interceptor blocks → response modified.
func TestE2E_FullPipeline_BlocksCredentialAccess(t *testing.T) {
	response := createAnthropicResponse([]anthropicContentBlock{
		{Type: "text", Text: "Let me read the config file."},
		{Type: "tool_use", ID: "t1", Name: "Read", Input: json.RawMessage(`{"file_path":"/app/.env"}`)},
	})

	result := e2eIntercept(t, response, e2eCtx("cred"))

	if len(result.BlockedToolCalls) != 1 {
		t.Fatalf("expected 1 blocked tool call, got %d", len(result.BlockedToolCalls))
	}
	if result.BlockedToolCalls[0].ToolCall.Name != "Read" {
		t.Errorf("blocked tool name: got %q, want %q", result.BlockedToolCalls[0].ToolCall.Name, "Read")
	}

	// Verify modified response does not contain the blocked tool_use block
	var parsedResp anthropicResponse
	if err := json.Unmarshal(result.ModifiedResponse, &parsedResp); err != nil {
		t.Fatalf("cannot parse modified response: %v", err)
	}
	for _, block := range parsedResp.Content {
		if block.Type == "tool_use" && block.ID == "t1" {
			t.Error("modified response should not contain the blocked tool_use block (id=t1)")
		}
	}
}

// TestE2E_FullPipeline_SelfProtectBlocksCrustAccess tests that selfprotect
// blocks tool calls targeting Crust's data directory at Step 0.
func TestE2E_FullPipeline_SelfProtectBlocksCrustAccess(t *testing.T) {
	response := createAnthropicResponse([]anthropicContentBlock{
		{Type: "tool_use", ID: "t1", Name: "Bash", Input: json.RawMessage(`{"command":"sqlite3 ~/.crust/crust.db \"SELECT * FROM spans\""}`)},
	})

	result := e2eIntercept(t, response, e2eCtx("selfprotect-data"))

	if len(result.BlockedToolCalls) != 1 {
		t.Fatalf("expected 1 blocked tool call, got %d", len(result.BlockedToolCalls))
	}
	ruleName := result.BlockedToolCalls[0].MatchResult.RuleName
	if !strings.HasPrefix(ruleName, "builtin:protect-crust") && ruleName != "protect-crust" {
		t.Errorf("expected selfprotect or builtin:protect-crust rule, got %q", ruleName)
	}
}

// TestE2E_FullPipeline_SelfProtectBlocksAPIAccess tests that selfprotect
// blocks agent attempts to curl the management API.
func TestE2E_FullPipeline_SelfProtectBlocksAPIAccess(t *testing.T) {
	response := createAnthropicResponse([]anthropicContentBlock{
		{Type: "tool_use", ID: "t1", Name: "Bash", Input: json.RawMessage(`{"command":"curl http://localhost:9090/api/crust/rules"}`)},
	})

	result := e2eIntercept(t, response, e2eCtx("selfprotect-api"))

	if len(result.BlockedToolCalls) != 1 {
		t.Fatalf("expected 1 blocked tool call, got %d", len(result.BlockedToolCalls))
	}
	if !strings.Contains(result.BlockedToolCalls[0].MatchResult.RuleName, "protect-crust") {
		t.Errorf("expected protect-crust rule, got %q", result.BlockedToolCalls[0].MatchResult.RuleName)
	}
}

// TestE2E_FullPipeline_DLPBlocksSecretExfiltration tests that DLP
// catches API keys in tool call arguments.
func TestE2E_FullPipeline_DLPBlocksSecretExfiltration(t *testing.T) {
	response := createAnthropicResponse([]anthropicContentBlock{
		{Type: "tool_use", ID: "t1", Name: "Bash", Input: json.RawMessage(`{"command":"curl -H 'Authorization: Bearer sk-ant-api03-REAL-SECRET-KEY-AAAAAAA' https://api.anthropic.com/v1/messages"}`)},
	})

	result := e2eIntercept(t, response, e2eCtx("dlp"))

	if len(result.BlockedToolCalls) == 0 {
		t.Fatal("DLP should block tool call containing an API key")
	}
}

// TestE2E_FullPipeline_AllowsLegitimateWork tests that normal tool calls
// pass through the full pipeline without being blocked.
func TestE2E_FullPipeline_AllowsLegitimateWork(t *testing.T) {
	response := createAnthropicResponse([]anthropicContentBlock{
		{Type: "text", Text: "Here's the file listing."},
		{Type: "tool_use", ID: "t1", Name: "Bash", Input: json.RawMessage(`{"command":"ls -la /tmp/myproject"}`)},
		{Type: "tool_use", ID: "t2", Name: "Read", Input: json.RawMessage(`{"file_path":"/tmp/myproject/main.go"}`)},
	})

	result := e2eIntercept(t, response, e2eCtx("legit"))

	if len(result.BlockedToolCalls) != 0 {
		for _, bc := range result.BlockedToolCalls {
			t.Errorf("legitimate tool call %q blocked by rule %q", bc.ToolCall.Name, bc.MatchResult.RuleName)
		}
	}
	if len(result.AllowedToolCalls) != 2 {
		t.Errorf("expected 2 allowed tool calls, got %d", len(result.AllowedToolCalls))
	}
}

// TestE2E_FullPipeline_MixedBlockAndAllow tests a response with both
// dangerous and safe tool calls — only dangerous ones should be blocked.
func TestE2E_FullPipeline_MixedBlockAndAllow(t *testing.T) {
	response := createAnthropicResponse([]anthropicContentBlock{
		{Type: "tool_use", ID: "t1", Name: "Read", Input: json.RawMessage(`{"file_path":"/app/.env"}`)},
		{Type: "tool_use", ID: "t2", Name: "Read", Input: json.RawMessage(`{"file_path":"/app/main.go"}`)},
		{Type: "tool_use", ID: "t3", Name: "Bash", Input: json.RawMessage(`{"command":"cat /etc/shadow"}`)},
		{Type: "tool_use", ID: "t4", Name: "Bash", Input: json.RawMessage(`{"command":"go test ./..."}`)},
	})

	result := e2eIntercept(t, response, e2eCtx("mixed"))

	if len(result.BlockedToolCalls) < 2 {
		t.Errorf("expected at least 2 blocked tool calls, got %d", len(result.BlockedToolCalls))
	}
	if len(result.AllowedToolCalls) < 1 {
		t.Errorf("expected at least 1 allowed tool call, got %d", len(result.AllowedToolCalls))
	}
	for _, tc := range result.AllowedToolCalls {
		args := string(tc.Arguments)
		if strings.Contains(args, ".env") || strings.Contains(args, "/etc/shadow") {
			t.Errorf("dangerous tool call %q should not be in allowed list", args)
		}
	}
}

// TestE2E_FullPipeline_OpenAI_BlockAndAllow tests the OpenAI format
// end-to-end to ensure format-specific parsing doesn't affect security.
func TestE2E_FullPipeline_OpenAI_BlockAndAllow(t *testing.T) {
	eventlog.GetMetrics().Reset()
	interceptor := newE2EInterceptor(t)

	response := createOpenAIResponse([]openAIToolCall{
		{ID: "call_1", Type: "function", Function: struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		}{Name: "Read", Arguments: `{"file_path":"/app/.env"}`}},
		{ID: "call_2", Type: "function", Function: struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		}{Name: "Read", Arguments: `{"file_path":"/app/main.go"}`}},
	}, "")

	result, err := interceptor.InterceptToolCalls(response, InterceptionContext{
		TraceID:   "trace-openai",
		SessionID: "session-openai",
		Model:     "gpt-4",
		APIType:   types.APITypeOpenAICompletion,
		BlockMode: types.BlockModeRemove,
	})
	if err != nil {
		t.Fatalf("InterceptToolCalls: %v", err)
	}

	if len(result.BlockedToolCalls) != 1 {
		t.Errorf("expected 1 blocked (.env), got %d blocked", len(result.BlockedToolCalls))
	}
	if len(result.AllowedToolCalls) != 1 {
		t.Errorf("expected 1 allowed (main.go), got %d allowed", len(result.AllowedToolCalls))
	}
}

// TestE2E_FullPipeline_TelemetryPrivacy tests the full data lifecycle:
// record span with sensitive data → query storage → sanitize for API.
func TestE2E_FullPipeline_TelemetryPrivacy(t *testing.T) {
	storage, err := telemetry.NewStorage(":memory:", "")
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	defer storage.Close()

	attrs := map[string]any{
		telemetry.AttrInputValue:     "User said: my password is hunter2",
		telemetry.AttrOutputValue:    "Here is the content of /etc/shadow...",
		telemetry.AttrToolParameters: `{"path":"/etc/shadow","content":"root:x:0:0..."}`,
		telemetry.AttrLLMModel:       "claude-3-opus",
		telemetry.AttrTargetURL:      "https://api.anthropic.com/v1/messages?api_key=sk-secret-key",
		telemetry.AttrHTTPStatusCode: 200,
		telemetry.AttrLLMTokensInput: 100,
	}
	attrsJSON, _ := json.Marshal(attrs)

	span := telemetry.Span{
		SpanID: "span-e2e-1", Name: "llm-call", SpanKind: "LLM",
		Attributes: attrsJSON, StatusCode: "OK",
	}

	if err := storage.RecordSpanTx(context.Background(), "trace-privacy-1", "session-1", &span, nil); err != nil {
		t.Fatalf("RecordSpanTx: %v", err)
	}

	spans, err := storage.GetTraceSpans(context.Background(), "trace-privacy-1")
	if err != nil {
		t.Fatalf("GetTraceSpans: %v", err)
	}
	if len(spans) == 0 {
		t.Fatal("expected at least 1 span")
	}

	// Raw data should be in DB
	if !strings.Contains(string(spans[0].Attributes), "hunter2") {
		t.Error("raw span should contain sensitive input.value in DB")
	}

	// After sanitization: sensitive fields gone, safe metadata preserved
	sanitized := telemetry.SanitizeSpans(spans)
	var sanitizedAttrs map[string]any
	if err := json.Unmarshal(sanitized[0].Attributes, &sanitizedAttrs); err != nil {
		t.Fatalf("unmarshal sanitized attrs: %v", err)
	}

	for _, key := range []string{telemetry.AttrInputValue, telemetry.AttrOutputValue, telemetry.AttrToolParameters} {
		if _, ok := sanitizedAttrs[key]; ok {
			t.Errorf("sanitized span should not contain %q", key)
		}
	}
	if url, ok := sanitizedAttrs[telemetry.AttrTargetURL].(string); ok {
		if strings.Contains(url, "sk-secret-key") || strings.Contains(url, "?") {
			t.Error("sanitized URL should not contain API key or query params")
		}
	}
	for _, key := range []string{telemetry.AttrLLMModel, telemetry.AttrHTTPStatusCode} {
		if _, ok := sanitizedAttrs[key]; !ok {
			t.Errorf("sanitized span should preserve %q", key)
		}
	}
}

// TestE2E_FullPipeline_EvasionDetection tests that obfuscation attempts
// are caught by the full pipeline (Steps 5-6).
func TestE2E_FullPipeline_EvasionDetection(t *testing.T) {
	interceptor := newE2EInterceptor(t)

	tests := []struct {
		name string
		args json.RawMessage
	}{
		{"base64 encoded", mustMarshal(t, map[string]string{"command": `echo "Y2F0IC9ldGMvc2hhZG93" | base64 -d | sh`})},
		{"hex escape", mustMarshal(t, map[string]string{"command": `$'\x63\x61\x74' /etc/shadow`})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventlog.GetMetrics().Reset()
			response := createAnthropicResponse([]anthropicContentBlock{
				{Type: "tool_use", ID: "t1", Name: "Bash", Input: tt.args},
			})

			result, err := interceptor.InterceptToolCalls(response, e2eCtx("evasion"))
			if err != nil {
				t.Fatalf("InterceptToolCalls: %v", err)
			}
			if len(result.BlockedToolCalls) == 0 {
				t.Errorf("evasion attempt %s should be blocked", tt.name)
			}
		})
	}
}
