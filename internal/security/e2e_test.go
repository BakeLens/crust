package security

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
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
//   selfprotect (Step 0) → rules engine (14-step) → interceptor → telemetry → privacy sanitization

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

// TestE2E_HotReloadRules verifies that adding rules to a live engine
// takes effect immediately for subsequent evaluations.
func TestE2E_HotReloadRules(t *testing.T) {
	eventlog.GetMetrics().Reset()
	interceptor := newE2EInterceptor(t)

	// This tool call should be allowed by default (no rule blocks /tmp/secret)
	response := createAnthropicResponse([]anthropicContentBlock{
		{Type: "tool_use", ID: "t1", Name: "Read", Input: json.RawMessage(`{"file_path":"/tmp/secret/data.txt"}`)},
	})

	result, err := interceptor.InterceptToolCalls(response, e2eCtx("reload-before"))
	if err != nil {
		t.Fatalf("InterceptToolCalls (before reload): %v", err)
	}
	if len(result.BlockedToolCalls) != 0 {
		t.Fatalf("expected 0 blocked before reload, got %d", len(result.BlockedToolCalls))
	}

	// Hot-reload: add a rule that blocks /tmp/secret/**
	err = interceptor.GetEngine().AddRulesFromYAML([]byte(`
rules:
  - name: block-tmp-secret
    message: Secret access blocked
    actions: [read, write]
    block: "/tmp/secret/**"
`))
	if err != nil {
		t.Fatalf("AddRulesFromYAML: %v", err)
	}

	// Same tool call should now be blocked
	result, err = interceptor.InterceptToolCalls(response, e2eCtx("reload-after"))
	if err != nil {
		t.Fatalf("InterceptToolCalls (after reload): %v", err)
	}
	if len(result.BlockedToolCalls) != 1 {
		t.Fatalf("expected 1 blocked after reload, got %d", len(result.BlockedToolCalls))
	}
	if result.BlockedToolCalls[0].MatchResult.RuleName != "block-tmp-secret" {
		t.Errorf("expected rule block-tmp-secret, got %q", result.BlockedToolCalls[0].MatchResult.RuleName)
	}
}

// TestE2E_CrossAPITypeConversion verifies that the same dangerous tool call
// is blocked regardless of API format (Anthropic, OpenAI, OpenAI Responses).
func TestE2E_CrossAPITypeConversion(t *testing.T) {
	interceptor := newE2EInterceptor(t)

	// Anthropic format
	t.Run("anthropic", func(t *testing.T) {
		eventlog.GetMetrics().Reset()
		resp := createAnthropicResponse([]anthropicContentBlock{
			{Type: "tool_use", ID: "t1", Name: "Read", Input: json.RawMessage(`{"file_path":"/app/.env"}`)},
		})
		result, err := interceptor.InterceptToolCalls(resp, InterceptionContext{
			TraceID: "trace-cross-1", SessionID: "sess-1",
			Model: "claude-3-opus", APIType: types.APITypeAnthropic, BlockMode: types.BlockModeRemove,
		})
		if err != nil {
			t.Fatalf("InterceptToolCalls: %v", err)
		}
		if len(result.BlockedToolCalls) != 1 {
			t.Errorf("Anthropic: expected 1 blocked, got %d", len(result.BlockedToolCalls))
		}
	})

	// OpenAI Completion format
	t.Run("openai", func(t *testing.T) {
		eventlog.GetMetrics().Reset()
		resp := createOpenAIResponse([]openAIToolCall{
			makeOAIToolCall("call_1", "Read", `{"file_path":"/app/.env"}`),
		}, "")
		result, err := interceptor.InterceptToolCalls(resp, InterceptionContext{
			TraceID: "trace-cross-2", SessionID: "sess-1",
			Model: "gpt-4", APIType: types.APITypeOpenAICompletion, BlockMode: types.BlockModeRemove,
		})
		if err != nil {
			t.Fatalf("InterceptToolCalls: %v", err)
		}
		if len(result.BlockedToolCalls) != 1 {
			t.Errorf("OpenAI: expected 1 blocked, got %d", len(result.BlockedToolCalls))
		}
	})

	// OpenAI Responses format
	t.Run("openai_responses", func(t *testing.T) {
		eventlog.GetMetrics().Reset()
		resp := createOpenAIResponsesResponse([]openAIResponsesOutputItem{
			{Type: "function_call", ID: "fc_1", CallID: "call_1", Name: "Read", Arguments: `{"file_path":"/app/.env"}`},
		})
		result, err := interceptor.InterceptToolCalls(resp, InterceptionContext{
			TraceID: "trace-cross-3", SessionID: "sess-1",
			Model: "gpt-4.1", APIType: types.APITypeOpenAIResponses, BlockMode: types.BlockModeRemove,
		})
		if err != nil {
			t.Fatalf("InterceptToolCalls: %v", err)
		}
		if len(result.BlockedToolCalls) != 1 {
			t.Errorf("OpenAI Responses: expected 1 blocked, got %d", len(result.BlockedToolCalls))
		}
	})
}

// TestE2E_ConcurrentEvaluationConsistency verifies that concurrent tool call
// evaluations produce consistent results under load.
func TestE2E_ConcurrentEvaluationConsistency(t *testing.T) {
	interceptor := newE2EInterceptor(t)
	eventlog.GetMetrics().Reset()

	dangerousResp := createAnthropicResponse([]anthropicContentBlock{
		{Type: "tool_use", ID: "t1", Name: "Read", Input: json.RawMessage(`{"file_path":"/app/.env"}`)},
	})
	safeResp := createAnthropicResponse([]anthropicContentBlock{
		{Type: "tool_use", ID: "t1", Name: "Read", Input: json.RawMessage(`{"file_path":"/tmp/safe.txt"}`)},
	})

	var wg sync.WaitGroup
	var blockedCount, allowedCount int64
	var mu sync.Mutex

	for i := range 20 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			resp := safeResp
			if idx%2 == 0 {
				resp = dangerousResp
			}
			result, err := interceptor.InterceptToolCalls(resp, e2eCtx("concurrent"))
			if err != nil {
				return
			}
			mu.Lock()
			blockedCount += int64(len(result.BlockedToolCalls))
			allowedCount += int64(len(result.AllowedToolCalls))
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	// 10 dangerous (even indices) should be blocked, 10 safe should be allowed
	if blockedCount != 10 {
		t.Errorf("expected 10 blocked, got %d", blockedCount)
	}
	if allowedCount != 10 {
		t.Errorf("expected 10 allowed, got %d", allowedCount)
	}
}

// TestE2E_MetricsReconcileAfterMixedTraffic verifies that metrics
// maintain the invariant: total = blocked + allowed after mixed traffic.
func TestE2E_MetricsReconcileAfterMixedTraffic(t *testing.T) {
	eventlog.GetMetrics().Reset()
	interceptor := newE2EInterceptor(t)

	// Send a mix of blocked and allowed tool calls
	responses := []struct {
		resp []byte
		ctx  InterceptionContext
	}{
		{createAnthropicResponse([]anthropicContentBlock{
			{Type: "tool_use", ID: "t1", Name: "Read", Input: json.RawMessage(`{"file_path":"/app/.env"}`)},
			{Type: "tool_use", ID: "t2", Name: "Read", Input: json.RawMessage(`{"file_path":"/tmp/ok.txt"}`)},
		}), e2eCtx("metrics-1")},
		{createOpenAIResponse([]openAIToolCall{
			makeOAIToolCall("c1", "Bash", `{"command":"cat /etc/shadow"}`),
			makeOAIToolCall("c2", "Bash", `{"command":"ls /tmp"}`),
		}, ""), InterceptionContext{
			TraceID: "trace-metrics-2", SessionID: "sess-1",
			Model: "gpt-4", APIType: types.APITypeOpenAICompletion, BlockMode: types.BlockModeRemove,
		}},
	}

	for _, r := range responses {
		if _, err := interceptor.InterceptToolCalls(r.resp, r.ctx); err != nil {
			t.Fatalf("InterceptToolCalls: %v", err)
		}
	}

	m := eventlog.GetMetrics()
	total := m.TotalToolCalls.Load()
	blocked := m.ProxyRequestBlocks.Load() + m.ProxyResponseBlocks.Load()
	allowed := m.ProxyResponseAllowed.Load()

	if total != blocked+allowed {
		t.Errorf("invariant broken: total(%d) != blocked(%d) + allowed(%d)", total, blocked, allowed)
	}
	if total == 0 {
		t.Error("expected non-zero total tool calls")
	}
}

// ── Mobile virtual path E2E tests ───────────────────────────────────────────

// TestE2E_MobilePIIBlocked verifies that mobile PII access (contacts, photos, etc.)
// is blocked by the protect-mobile-pii builtin rule via virtual paths.
func TestE2E_MobilePIIBlocked(t *testing.T) {
	tools := []struct {
		name string
		args string
	}{
		{"read_contacts", `{}`},
		{"access_photos", `{}`},
		{"read_calendar", `{}`},
		{"get_location", `{}`},
		{"read_health_data", `{}`},
	}

	for _, tt := range tools {
		t.Run(tt.name, func(t *testing.T) {
			response := createAnthropicResponse([]anthropicContentBlock{
				{Type: "tool_use", ID: "m1", Name: tt.name, Input: json.RawMessage(tt.args)},
			})
			result := e2eIntercept(t, response, e2eCtx("mobile-pii"))
			if len(result.BlockedToolCalls) != 1 {
				t.Fatalf("expected %s to be blocked, got %d blocked", tt.name, len(result.BlockedToolCalls))
			}
			if !strings.Contains(result.BlockedToolCalls[0].MatchResult.Message, "privacy") {
				t.Errorf("expected privacy-related message, got: %s", result.BlockedToolCalls[0].MatchResult.Message)
			}
		})
	}
}

// TestE2E_MobileKeychainBlocked verifies that keychain access is blocked by
// the unified protect-os-keychains rule (which now includes mobile://keychain/**).
func TestE2E_MobileKeychainBlocked(t *testing.T) {
	response := createAnthropicResponse([]anthropicContentBlock{
		{Type: "tool_use", ID: "k1", Name: "keychain_get", Input: json.RawMessage(`{"key":"api_token"}`)},
	})
	result := e2eIntercept(t, response, e2eCtx("mobile-keychain"))
	if len(result.BlockedToolCalls) != 1 {
		t.Fatalf("expected keychain_get to be blocked, got %d blocked", len(result.BlockedToolCalls))
	}
	if !strings.Contains(result.BlockedToolCalls[0].MatchResult.Message, "keychain") {
		t.Errorf("expected keychain-related message, got: %s", result.BlockedToolCalls[0].MatchResult.Message)
	}
}

// TestE2E_MobileURLSchemeBlocked verifies that sensitive URL schemes (tel:, sms:)
// are blocked while safe ones (https:) are allowed.
func TestE2E_MobileURLSchemeBlocked(t *testing.T) {
	// tel: should be blocked
	response := createAnthropicResponse([]anthropicContentBlock{
		{Type: "tool_use", ID: "u1", Name: "open_url", Input: json.RawMessage(`{"url":"tel:+1234567890"}`)},
	})
	result := e2eIntercept(t, response, e2eCtx("mobile-url-blocked"))
	if len(result.BlockedToolCalls) != 1 {
		t.Fatalf("expected tel: URL to be blocked, got %d blocked", len(result.BlockedToolCalls))
	}

	// https: should be allowed
	response = createAnthropicResponse([]anthropicContentBlock{
		{Type: "tool_use", ID: "u2", Name: "open_url", Input: json.RawMessage(`{"url":"https://example.com"}`)},
	})
	result = e2eIntercept(t, response, e2eCtx("mobile-url-allowed"))
	if len(result.BlockedToolCalls) != 0 {
		t.Fatalf("expected https: URL to be allowed, got %d blocked", len(result.BlockedToolCalls))
	}
}

// TestE2E_MobileClipboardReadBlocked verifies that clipboard reads are blocked
// while clipboard writes are allowed.
func TestE2E_MobileClipboardReadBlocked(t *testing.T) {
	// read_clipboard should be blocked
	response := createAnthropicResponse([]anthropicContentBlock{
		{Type: "tool_use", ID: "c1", Name: "read_clipboard", Input: json.RawMessage(`{}`)},
	})
	result := e2eIntercept(t, response, e2eCtx("mobile-clipboard-read"))
	if len(result.BlockedToolCalls) != 1 {
		t.Fatalf("expected read_clipboard to be blocked, got %d blocked", len(result.BlockedToolCalls))
	}

	// write_clipboard should be allowed (rule only blocks reads)
	response = createAnthropicResponse([]anthropicContentBlock{
		{Type: "tool_use", ID: "c2", Name: "write_clipboard", Input: json.RawMessage(`{}`)},
	})
	result = e2eIntercept(t, response, e2eCtx("mobile-clipboard-write"))
	if len(result.BlockedToolCalls) != 0 {
		t.Fatalf("expected write_clipboard to be allowed, got %d blocked", len(result.BlockedToolCalls))
	}
}

// TestE2E_MobilePersistenceBlocked verifies that mobile background task registration
// is blocked by the unified protect-persistence rule.
func TestE2E_MobilePersistenceBlocked(t *testing.T) {
	response := createAnthropicResponse([]anthropicContentBlock{
		{Type: "tool_use", ID: "p1", Name: "schedule_task", Input: json.RawMessage(`{"task_id":"sync_data"}`)},
	})
	result := e2eIntercept(t, response, e2eCtx("mobile-persistence"))
	if len(result.BlockedToolCalls) != 1 {
		t.Fatalf("expected schedule_task to be blocked, got %d blocked", len(result.BlockedToolCalls))
	}
	if !strings.Contains(result.BlockedToolCalls[0].MatchResult.Message, "persistence") {
		t.Errorf("expected persistence-related message, got: %s", result.BlockedToolCalls[0].MatchResult.Message)
	}
}

// TestE2E_DesktopRulesStillWork verifies mobile changes don't break desktop rules.
func TestE2E_DesktopRulesStillWork(t *testing.T) {
	// Desktop .env read should still be blocked
	response := createAnthropicResponse([]anthropicContentBlock{
		{Type: "tool_use", ID: "d1", Name: "Read", Input: json.RawMessage(`{"file_path":"/app/.env"}`)},
	})
	result := e2eIntercept(t, response, e2eCtx("desktop-regression"))
	if len(result.BlockedToolCalls) != 1 {
		t.Fatalf("expected desktop .env read to still be blocked, got %d blocked", len(result.BlockedToolCalls))
	}

	// Desktop /etc/crontab write should still be blocked
	response = createAnthropicResponse([]anthropicContentBlock{
		{Type: "tool_use", ID: "d2", Name: "Write", Input: json.RawMessage(`{"file_path":"/etc/crontab","content":"* * * * * evil"}`)},
	})
	result = e2eIntercept(t, response, e2eCtx("desktop-persistence"))
	if len(result.BlockedToolCalls) != 1 {
		t.Fatalf("expected desktop crontab write to still be blocked, got %d blocked", len(result.BlockedToolCalls))
	}
}
