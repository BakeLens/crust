package security

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BakeLens/crust/internal/eventlog"
	"github.com/BakeLens/crust/internal/message"
	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/types"
)

// --- Test helpers ---

// openaiCtx returns an InterceptionContext for OpenAI tests.
func openaiCtx(mode types.BlockMode) InterceptionContext {
	return InterceptionContext{
		TraceID: "trace-1", SessionID: "session-1",
		Model: "gpt-4", APIType: types.APITypeOpenAICompletion, BlockMode: mode,
	}
}

// anthropicCtx returns an InterceptionContext for Anthropic tests.
func anthropicCtx(mode types.BlockMode) InterceptionContext {
	return InterceptionContext{
		TraceID: "trace-1", SessionID: "session-1",
		Model: "claude-3-opus", APIType: types.APITypeAnthropic, BlockMode: mode,
	}
}

// makeOAIToolCall builds an openAIToolCall without the verbose anonymous struct.
func makeOAIToolCall(id, name, args string) openAIToolCall {
	return openAIToolCall{
		ID:   id,
		Type: "function",
		Function: struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		}{Name: name, Arguments: args},
	}
}

// createOpenAIResponse creates a test OpenAI response JSON.
func createOpenAIResponse(toolCalls []openAIToolCall, content string) []byte {
	resp := openAIResponse{
		ID: "test-id", Object: "chat.completion", Created: 1234567890, Model: "gpt-4",
		Choices: []openAIChoice{{
			Index: 0,
			Message: openAIMessage{
				Role: "assistant", Content: content, ToolCalls: toolCalls,
			},
			FinishReason: "tool_calls",
		}},
	}
	data, _ := json.Marshal(resp)
	return data
}

// createAnthropicResponse creates a test Anthropic response JSON.
func createAnthropicResponse(content []anthropicContentBlock) []byte {
	resp := anthropicResponse{
		ID: "test-id", Type: "message", Role: "assistant",
		Content: content, Model: "claude-3-opus", StopReason: "tool_use",
	}
	data, _ := json.Marshal(resp)
	return data
}

// createOpenAIResponsesResponse creates a test OpenAI Responses API response JSON.
func createOpenAIResponsesResponse(output []openAIResponsesOutputItem) []byte {
	resp := openAIResponsesResponse{
		ID: "resp-test", Object: "response", Model: "gpt-4.1",
		Output: output,
	}
	data, _ := json.Marshal(resp)
	return data
}

// credentialAccessRule is a reusable test rule that blocks reading .env files.
const credentialAccessRule = `
rules:
  - name: block-env-file
    block: "**/.env"
    actions: [read]
    message: "Credential file access blocked"
    severity: critical
`

// setupTestRulesDir creates a temporary directory with test rules.
func setupTestRulesDir(t *testing.T, rulesYAML string) string {
	t.Helper()
	rulesDir := filepath.Join(t.TempDir(), "rules")
	if err := os.MkdirAll(rulesDir, 0700); err != nil {
		t.Fatalf("Failed to create rules dir: %v", err)
	}
	if rulesYAML != "" {
		if err := os.WriteFile(filepath.Join(rulesDir, "test-rules.yaml"), []byte(rulesYAML), 0644); err != nil {
			t.Fatalf("Failed to write test rules: %v", err)
		}
	}
	return rulesDir
}

// createTestInterceptor creates an interceptor with custom rules for testing.
func createTestInterceptor(t *testing.T, rulesYAML string) *Interceptor {
	t.Helper()
	tempDir := setupTestRulesDir(t, rulesYAML)
	engine, err := rules.NewEngine(context.Background(), rules.EngineConfig{
		UserRulesDir:   tempDir,
		DisableBuiltin: true,
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

// TestInterceptOpenAIResponse_BlockDangerousTool tests blocking dangerous tool calls in OpenAI format
func TestInterceptOpenAIResponse_BlockDangerousTool(t *testing.T) {
	tests := []struct {
		name             string
		rulesYAML        string
		toolName         string
		arguments        string
		blockMode        types.BlockMode
		wantBlocked      bool
		wantToolRemoved  bool
		wantWarningInMsg bool
	}{
		{
			name: "block rm on root in remove mode",
			rulesYAML: `
rules:
  - name: block-dangerous-rm
    block: "/"
    actions: [delete]
    message: "Dangerous command blocked"
    severity: critical
`,
			toolName:         "Bash",
			arguments:        `{"command": "rm -rf /"}`,
			blockMode:        types.BlockModeRemove,
			wantBlocked:      true,
			wantToolRemoved:  true,
			wantWarningInMsg: true,
		},
		{
			name: "block rm on root in replace mode",
			rulesYAML: `
rules:
  - name: block-dangerous-rm
    block: "/"
    actions: [delete]
    message: "Dangerous command blocked"
    severity: critical
`,
			toolName:         "Bash",
			arguments:        `{"command": "rm -rf /"}`,
			blockMode:        types.BlockModeReplace,
			wantBlocked:      true,
			wantToolRemoved:  true,
			wantWarningInMsg: true,
		},
		{
			name: "allow safe command",
			rulesYAML: `
rules:
  - name: block-dangerous-rm
    block: "/"
    actions: [delete]
    message: "Dangerous command blocked"
    severity: critical
`,
			toolName:         "Bash",
			arguments:        `{"command": "ls -la"}`,
			blockMode:        types.BlockModeRemove,
			wantBlocked:      false,
			wantToolRemoved:  false,
			wantWarningInMsg: false,
		},
		{
			name: "block credential file read",
			rulesYAML: `
rules:
  - name: block-env-file
    block: "**/.env"
    actions: [read]
    message: "Credential file access blocked"
    severity: critical
`,
			toolName:         "Read",
			arguments:        `{"file_path": "/home/user/.env"}`,
			blockMode:        types.BlockModeRemove,
			wantBlocked:      true,
			wantToolRemoved:  true,
			wantWarningInMsg: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset metrics before each test
			eventlog.GetMetrics().Reset()

			interceptor := createTestInterceptor(t, tt.rulesYAML)

			responseBody := createOpenAIResponse([]openAIToolCall{makeOAIToolCall("call_123", tt.toolName, tt.arguments)}, "")

			result, err := interceptor.InterceptOpenAIResponse(responseBody, openaiCtx(tt.blockMode))

			if err != nil {
				t.Fatalf("InterceptOpenAIResponse returned error: %v", err)
			}

			// Verify blocked status
			if (len(result.BlockedToolCalls) > 0) != tt.wantBlocked {
				t.Errorf("HasBlockedCalls = %v, want %v", len(result.BlockedToolCalls) > 0, tt.wantBlocked)
			}

			// Verify tool was removed/kept
			var parsedResp openAIResponse
			if err := json.Unmarshal(result.ModifiedResponse, &parsedResp); err != nil {
				t.Fatalf("Failed to parse modified response: %v", err)
			}

			if len(parsedResp.Choices) == 0 {
				t.Fatal("Modified response has no choices")
			}

			toolCount := len(parsedResp.Choices[0].Message.ToolCalls)
			if tt.wantToolRemoved && toolCount != 0 {
				t.Errorf("Expected tool to be removed, but found %d tool calls", toolCount)
			}
			if !tt.wantToolRemoved && toolCount == 0 {
				t.Errorf("Expected tool to be kept, but no tool calls found")
			}

			// Verify warning message
			hasWarning := parsedResp.Choices[0].Message.Content != ""
			if tt.wantWarningInMsg && !hasWarning {
				t.Errorf("Expected warning message in content, but content is empty")
			}
			if !tt.wantWarningInMsg && hasWarning {
				t.Errorf("Expected no warning message, but got: %s", parsedResp.Choices[0].Message.Content)
			}
		})
	}
}

// TestInterceptOpenAIResponse_MultipleToolCalls tests handling multiple tool calls
func TestInterceptOpenAIResponse_MultipleToolCalls(t *testing.T) {
	// Reset metrics
	eventlog.GetMetrics().Reset()

	rulesYAML := `
rules:
  - name: block-rm
    block: "/"
    actions: [delete]
    message: "Blocked rm -rf"
    severity: critical
`

	interceptor := createTestInterceptor(t, rulesYAML)

	toolCalls := []openAIToolCall{
		makeOAIToolCall("call_1", "Bash", `{"command": "rm -rf /"}`),
		makeOAIToolCall("call_2", "Bash", `{"command": "ls -la"}`),
		makeOAIToolCall("call_3", "Read", `{"file_path": "/tmp/test.txt"}`),
	}
	responseBody := createOpenAIResponse(toolCalls, "")
	result, err := interceptor.InterceptOpenAIResponse(responseBody, openaiCtx(types.BlockModeRemove))

	if err != nil {
		t.Fatalf("InterceptOpenAIResponse returned error: %v", err)
	}

	// Should have 1 blocked call and 2 allowed calls
	if len(result.BlockedToolCalls) != 1 {
		t.Errorf("Expected 1 blocked tool call, got %d", len(result.BlockedToolCalls))
	}
	if len(result.AllowedToolCalls) != 2 {
		t.Errorf("Expected 2 allowed tool calls, got %d", len(result.AllowedToolCalls))
	}

	// Parse modified response
	var parsedResp openAIResponse
	if err := json.Unmarshal(result.ModifiedResponse, &parsedResp); err != nil {
		t.Fatalf("Failed to parse modified response: %v", err)
	}

	// Should have 2 tool calls remaining
	if len(parsedResp.Choices[0].Message.ToolCalls) != 2 {
		t.Errorf("Expected 2 tool calls in response, got %d", len(parsedResp.Choices[0].Message.ToolCalls))
	}

	// Verify the blocked one is not in the response
	for _, tc := range parsedResp.Choices[0].Message.ToolCalls {
		if tc.ID == "call_1" {
			t.Error("Blocked tool call (call_1) should not be in response")
		}
	}
}

// TestInterceptOpenAIResponse_EmptyResponse tests handling empty responses
func TestInterceptOpenAIResponse_EmptyResponse(t *testing.T) {
	interceptor := createTestInterceptor(t, "")

	tests := []struct {
		name         string
		responseBody []byte
		wantError    bool
	}{
		{
			name:         "empty body",
			responseBody: []byte{},
			wantError:    false,
		},
		{
			name:         "invalid json",
			responseBody: []byte("not json"),
			wantError:    false,
		},
		{
			name:         "empty choices",
			responseBody: []byte(`{"choices": []}`),
			wantError:    false,
		},
		{
			name:         "no tool calls",
			responseBody: createOpenAIResponse(nil, "Hello, world!"),
			wantError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := interceptor.InterceptOpenAIResponse(tt.responseBody, openaiCtx(types.BlockModeRemove))

			if tt.wantError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// Should return original body unchanged for invalid/empty responses
			if string(result.ModifiedResponse) != string(tt.responseBody) {
				t.Errorf("Expected response to be unchanged")
			}
		})
	}
}

// TestInterceptOpenAIResponse_DisabledInterceptor tests that disabled interceptor passes through
func TestInterceptOpenAIResponse_DisabledInterceptor(t *testing.T) {
	rulesYAML := `
rules:
  - name: block-all
    block: "/**"
    actions: [read, write, delete, copy, move, execute]
    message: "Blocked"
    severity: critical
`
	interceptor := createTestInterceptor(t, rulesYAML)

	interceptor.SetEnabled(false)

	responseBody := createOpenAIResponse([]openAIToolCall{makeOAIToolCall("call_1", "Bash", `{"command": "rm -rf /"}`)}, "")
	result, err := interceptor.InterceptOpenAIResponse(responseBody, openaiCtx(types.BlockModeRemove))

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Response should be unchanged when interceptor is disabled
	if string(result.ModifiedResponse) != string(responseBody) {
		t.Error("Expected response to be unchanged when interceptor is disabled")
	}

	// No blocked calls should be recorded
	if len(result.BlockedToolCalls) > 0 {
		t.Error("HasBlockedCalls should be false when interceptor is disabled")
	}
}

// TestInterceptAnthropicResponse_BlockDangerousTool tests blocking in Anthropic format
func TestInterceptAnthropicResponse_BlockDangerousTool(t *testing.T) {
	tests := []struct {
		name            string
		rulesYAML       string
		toolName        string
		input           string
		blockMode       types.BlockMode
		wantBlocked     bool
		wantToolRemoved bool
		wantTextBlock   bool // Warning text block added
	}{
		{
			name: "block dangerous command remove mode",
			rulesYAML: `
rules:
  - name: block-rm
    block: "/"
    actions: [delete]
    message: "Blocked"
    severity: critical
`,
			toolName:        "Bash",
			input:           `{"command": "rm -rf /"}`,
			blockMode:       types.BlockModeRemove,
			wantBlocked:     true,
			wantToolRemoved: true,
			wantTextBlock:   true, // Warning text block added in remove mode
		},
		{
			name: "block dangerous command replace mode",
			rulesYAML: `
rules:
  - name: block-rm
    block: "/"
    actions: [delete]
    message: "Blocked"
    severity: critical
`,
			toolName:        "Bash",
			input:           `{"command": "rm -rf /"}`,
			blockMode:       types.BlockModeReplace,
			wantBlocked:     true,
			wantToolRemoved: true,
			wantTextBlock:   true, // Replaced with text block in replace mode
		},
		{
			name: "allow safe command",
			rulesYAML: `
rules:
  - name: block-rm
    block: "/"
    actions: [delete]
    message: "Blocked"
    severity: critical
`,
			toolName:        "Bash",
			input:           `{"command": "ls -la"}`,
			blockMode:       types.BlockModeRemove,
			wantBlocked:     false,
			wantToolRemoved: false,
			wantTextBlock:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventlog.GetMetrics().Reset()

			interceptor := createTestInterceptor(t, tt.rulesYAML)

			// Create Anthropic response
			content := []anthropicContentBlock{
				{
					Type:  "tool_use",
					ID:    "toolu_123",
					Name:  tt.toolName,
					Input: json.RawMessage(tt.input),
				},
			}
			responseBody := createAnthropicResponse(content)

			result, err := interceptor.InterceptAnthropicResponse(responseBody, anthropicCtx(tt.blockMode))

			if err != nil {
				t.Fatalf("InterceptAnthropicResponse returned error: %v", err)
			}

			if (len(result.BlockedToolCalls) > 0) != tt.wantBlocked {
				t.Errorf("HasBlockedCalls = %v, want %v", len(result.BlockedToolCalls) > 0, tt.wantBlocked)
			}

			// Parse modified response
			var parsedResp anthropicResponse
			if err := json.Unmarshal(result.ModifiedResponse, &parsedResp); err != nil {
				t.Fatalf("Failed to parse modified response: %v", err)
			}

			// Check tool_use blocks
			toolUseCount := 0
			textBlockCount := 0
			for _, block := range parsedResp.Content {
				if block.Type == "tool_use" {
					toolUseCount++
				}
				if block.Type == "text" {
					textBlockCount++
				}
			}

			if tt.wantToolRemoved && toolUseCount != 0 {
				t.Errorf("Expected tool_use to be removed, found %d", toolUseCount)
			}
			if !tt.wantToolRemoved && toolUseCount == 0 {
				t.Errorf("Expected tool_use to be kept, but none found")
			}
			if tt.wantTextBlock && textBlockCount == 0 {
				t.Errorf("Expected text block (warning/replacement), but none found")
			}
		})
	}
}

// TestInterceptAnthropicResponse_TextBlockPassThrough tests that text blocks are unchanged
func TestInterceptAnthropicResponse_TextBlockPassThrough(t *testing.T) {
	interceptor := createTestInterceptor(t, "")

	// Create response with only text blocks
	content := []anthropicContentBlock{
		{
			Type: "text",
			Text: "Hello, this is a text response.",
		},
		{
			Type: "text",
			Text: "Another text block.",
		},
	}
	responseBody := createAnthropicResponse(content)

	result, err := interceptor.InterceptAnthropicResponse(responseBody, anthropicCtx(types.BlockModeRemove))

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should not have any blocked calls
	if len(result.BlockedToolCalls) > 0 {
		t.Error("Expected no blocked calls for text-only response")
	}

	// Response should be unchanged
	var parsedResp anthropicResponse
	if err := json.Unmarshal(result.ModifiedResponse, &parsedResp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if len(parsedResp.Content) != 2 {
		t.Errorf("Expected 2 content blocks, got %d", len(parsedResp.Content))
	}
	for _, block := range parsedResp.Content {
		if block.Type != "text" {
			t.Errorf("Expected all blocks to be text, got %s", block.Type)
		}
	}
}

// TestInterceptAnthropicResponse_MixedContent tests mixed text and tool_use blocks
func TestInterceptAnthropicResponse_MixedContent(t *testing.T) {
	eventlog.GetMetrics().Reset()

	rulesYAML := `
rules:
  - name: block-root-delete
    block: "/"
    actions: [delete]
    message: "Bash blocked"
    severity: critical
`
	interceptor := createTestInterceptor(t, rulesYAML)

	content := []anthropicContentBlock{
		{
			Type: "text",
			Text: "Let me help you with that.",
		},
		{
			Type:  "tool_use",
			ID:    "toolu_1",
			Name:  "Bash",
			Input: json.RawMessage(`{"command": "rm -rf /"}`),
		},
		{
			Type:  "tool_use",
			ID:    "toolu_2",
			Name:  "Read",
			Input: json.RawMessage(`{"file_path": "/tmp/test.txt"}`),
		},
		{
			Type: "text",
			Text: "Additional text.",
		},
	}
	responseBody := createAnthropicResponse(content)

	result, err := interceptor.InterceptAnthropicResponse(responseBody, anthropicCtx(types.BlockModeRemove))

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(result.BlockedToolCalls) != 1 {
		t.Errorf("Expected 1 blocked call, got %d", len(result.BlockedToolCalls))
	}
	if len(result.AllowedToolCalls) != 1 {
		t.Errorf("Expected 1 allowed call, got %d", len(result.AllowedToolCalls))
	}

	var parsedResp anthropicResponse
	if err := json.Unmarshal(result.ModifiedResponse, &parsedResp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Should have: 2 original text blocks + 1 allowed tool_use + 1 warning text block
	textCount := 0
	toolUseCount := 0
	for _, block := range parsedResp.Content {
		if block.Type == "text" {
			textCount++
		}
		if block.Type == "tool_use" {
			toolUseCount++
		}
	}

	if toolUseCount != 1 {
		t.Errorf("Expected 1 tool_use block, got %d", toolUseCount)
	}
	// 2 original text blocks + 1 warning = 3
	if textCount < 3 {
		t.Errorf("Expected at least 3 text blocks (2 original + 1 warning), got %d", textCount)
	}
}

// TestInterceptToolCalls_RoutesToCorrectHandler tests API type routing
func TestInterceptToolCalls_RoutesToCorrectHandler(t *testing.T) {
	tests := []struct {
		name    string
		apiType types.APIType
	}{
		{
			name:    "routes to OpenAI handler",
			apiType: types.APITypeOpenAICompletion,
		},
		{
			name:    "routes to Anthropic handler",
			apiType: types.APITypeAnthropic,
		},
		{
			name:    "defaults to OpenAI for unknown",
			apiType: types.APITypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interceptor := createTestInterceptor(t, "")

			var responseBody []byte
			if tt.apiType == types.APITypeAnthropic {
				responseBody = createAnthropicResponse([]anthropicContentBlock{
					{Type: "text", Text: "Hello"},
				})
			} else {
				responseBody = createOpenAIResponse(nil, "Hello")
			}

			result, err := interceptor.InterceptToolCalls(responseBody, InterceptionContext{
				TraceID: "trace-1", SessionID: "session-1",
				Model: "test-model", APIType: tt.apiType, BlockMode: types.BlockModeRemove,
			})

			if err != nil {
				t.Errorf("InterceptToolCalls returned error: %v", err)
			}

			// Should successfully parse and return
			if result.ModifiedResponse == nil {
				t.Error("ModifiedResponse should not be nil")
			}
		})
	}
}

// TestInterceptOpenAIResponse_NilEngine tests handling nil engine
func TestInterceptOpenAIResponse_NilEngine(t *testing.T) {
	interceptor := &Interceptor{
		engine:  nil,
		storage: nil,
	}
	interceptor.enabled.Store(true)

	responseBody := createOpenAIResponse([]openAIToolCall{makeOAIToolCall("call_1", "Bash", `{"command": "rm -rf /"}`)}, "")
	result, err := interceptor.InterceptOpenAIResponse(responseBody, openaiCtx(types.BlockModeRemove))

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
		return
	}

	// Should pass through unchanged when engine is nil
	if string(result.ModifiedResponse) != string(responseBody) {
		t.Error("Expected response to be unchanged when engine is nil")
	}
}

// TestBuildWarningContent tests the warning message builder
func TestBuildWarningContent(t *testing.T) {
	tests := []struct {
		name         string
		blockedCalls []BlockedToolCall
		wantContains []string
	}{
		{
			name: "single blocked call with message",
			blockedCalls: []BlockedToolCall{
				{
					ToolCall: telemetry.ToolCall{
						Name: "Bash",
					},
					MatchResult: rules.MatchResult{
						Message: "Dangerous command",
					},
				},
			},
			wantContains: []string{"[Crust]", "Bash", "Dangerous command", "Do not retry"},
		},
		{
			name: "multiple blocked calls",
			blockedCalls: []BlockedToolCall{
				{
					ToolCall: telemetry.ToolCall{
						Name: "Bash",
					},
					MatchResult: rules.MatchResult{
						Message: "Blocked rm",
					},
				},
				{
					ToolCall: telemetry.ToolCall{
						Name: "Read",
					},
					MatchResult: rules.MatchResult{
						Message: "Blocked credential read",
					},
				},
			},
			wantContains: []string{"[Crust]", "Bash", "Read", "Blocked rm", "Blocked credential read", "Do not retry"},
		},
		{
			name: "blocked call without message",
			blockedCalls: []BlockedToolCall{
				{
					ToolCall: telemetry.ToolCall{
						Name: "Write",
					},
					MatchResult: rules.MatchResult{},
				},
			},
			wantContains: []string{"[Crust]", "Write", "Do not retry"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BuildWarningContent(tt.blockedCalls)

			for _, want := range tt.wantContains {
				if !strings.Contains(result, want) {
					t.Errorf("BuildWarningContent() = %q, want to contain %q", result, want)
				}
			}
		})
	}
}

// TestFormatReplaceDetail tests the replace message detail formatter (via message package).
func TestFormatReplaceDetail(t *testing.T) {
	tests := []struct {
		name         string
		matchResult  rules.MatchResult
		wantContains string
	}{
		{
			name: "with custom message",
			matchResult: rules.MatchResult{
				Message:  "Custom block reason",
				RuleName: "test-rule",
			},
			wantContains: "Custom block reason (rule: test-rule)",
		},
		{
			name: "without custom message",
			matchResult: rules.MatchResult{
				RuleName: "test-rule",
			},
			wantContains: "blocked by rule: test-rule",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := message.FormatReplaceDetail(tt.matchResult)
			if result != tt.wantContains {
				t.Errorf("FormatReplaceDetail() = %q, want %q", result, tt.wantContains)
			}
		})
	}
}

// TestFormatReplaceWarning tests the replace warning builder (via message package).
func TestFormatReplaceWarning(t *testing.T) {
	blocked := []message.BlockedCall{
		{
			ToolName: "Bash",
			MatchResult: rules.MatchResult{
				RuleName: "block-bash",
				Message:  "Dangerous",
			},
		},
	}

	result := message.FormatReplaceWarning(blocked)

	wantContains := []string{
		"[Crust]",
		"blocked",
		"Bash",
		"Dangerous",
		"block-bash",
		"Do not retry",
	}

	for _, want := range wantContains {
		if !strings.Contains(result, want) {
			t.Errorf("FormatReplaceWarning() = %q, want to contain %q", result, want)
		}
	}
}

// TestInterceptorEnableDisable tests enable/disable functionality
func TestInterceptorEnableDisable(t *testing.T) {
	interceptor := createTestInterceptor(t, "")

	// Should be enabled by default
	if !interceptor.IsEnabled() {
		t.Error("Interceptor should be enabled by default")
	}

	// Disable
	interceptor.SetEnabled(false)
	if interceptor.IsEnabled() {
		t.Error("Interceptor should be disabled after SetEnabled(false)")
	}

	// Re-enable
	interceptor.SetEnabled(true)
	if !interceptor.IsEnabled() {
		t.Error("Interceptor should be enabled after SetEnabled(true)")
	}
}

// TestInterceptorGetters tests getter methods
func TestInterceptorGetters(t *testing.T) {
	interceptor := createTestInterceptor(t, "")

	if interceptor.GetEngine() == nil {
		t.Error("GetEngine() should not return nil")
	}

	if interceptor.GetStorage() == nil {
		t.Error("GetStorage() should not return nil")
	}
}

// TestInterceptOpenAIResponse_ExistingContentPreserved tests that existing content is preserved
func TestInterceptOpenAIResponse_ExistingContentPreserved(t *testing.T) {
	eventlog.GetMetrics().Reset()

	rulesYAML := `
rules:
  - name: block-rule
    block: "/"
    actions: [delete]
    message: "Blocked"
    severity: critical
`
	interceptor := createTestInterceptor(t, rulesYAML)

	existingContent := "I will help you with that task."
	responseBody := createOpenAIResponse([]openAIToolCall{makeOAIToolCall("call_1", "Bash", `{"command": "rm -rf /"}`)}, existingContent)
	result, err := interceptor.InterceptOpenAIResponse(responseBody, openaiCtx(types.BlockModeRemove))

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	var parsedResp openAIResponse
	if err := json.Unmarshal(result.ModifiedResponse, &parsedResp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Content should contain both the original content and the warning
	content := parsedResp.Choices[0].Message.Content
	if !strings.Contains(content, existingContent) {
		t.Errorf("Original content should be preserved, got: %s", content)
	}
	if !strings.Contains(content, "[Crust]") {
		t.Errorf("Warning should be appended, got: %s", content)
	}
}

// TestInterceptOpenAIResponse_MalformedToolCallArguments tests handling malformed arguments
func TestInterceptOpenAIResponse_MalformedToolCallArguments(t *testing.T) {
	rulesYAML := `
rules:
  - name: block-rm
    block: "/"
    actions: [delete]
    message: "Blocked"
    severity: critical
`
	interceptor := createTestInterceptor(t, rulesYAML)

	responseBody := createOpenAIResponse([]openAIToolCall{makeOAIToolCall("call_1", "Bash", `not-valid-json`)}, "")
	result, err := interceptor.InterceptOpenAIResponse(responseBody, openaiCtx(types.BlockModeRemove))

	// Should not error, just treat as non-matching
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
		return
	}

	// Should not block because the pattern can't match invalid JSON
	if len(result.BlockedToolCalls) > 0 {
		t.Error("Should not block tool calls with malformed arguments that don't match pattern")
	}
}

// TestInterceptAnthropicResponse_DisabledInterceptor tests disabled interceptor for Anthropic
func TestInterceptAnthropicResponse_DisabledInterceptor(t *testing.T) {
	rulesYAML := `
rules:
  - name: block-all
    block: "/**"
    actions: [read, write, delete, copy, move, execute]
    message: "Blocked"
    severity: critical
`
	interceptor := createTestInterceptor(t, rulesYAML)

	interceptor.SetEnabled(false)

	content := []anthropicContentBlock{
		{
			Type:  "tool_use",
			ID:    "toolu_1",
			Name:  "Bash",
			Input: json.RawMessage(`{"command": "rm -rf /"}`),
		},
	}
	responseBody := createAnthropicResponse(content)

	result, err := interceptor.InterceptAnthropicResponse(responseBody, anthropicCtx(types.BlockModeRemove))

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Response should be unchanged when interceptor is disabled
	if string(result.ModifiedResponse) != string(responseBody) {
		t.Error("Expected response to be unchanged when interceptor is disabled")
	}

	if len(result.BlockedToolCalls) > 0 {
		t.Error("HasBlockedCalls should be false when interceptor is disabled")
	}
}

// TestInterceptAnthropicResponse_NilEngine tests nil engine handling for Anthropic
func TestInterceptAnthropicResponse_NilEngine(t *testing.T) {
	interceptor := &Interceptor{
		engine:  nil,
		storage: nil,
	}
	interceptor.enabled.Store(true)

	content := []anthropicContentBlock{
		{
			Type:  "tool_use",
			ID:    "toolu_1",
			Name:  "Bash",
			Input: json.RawMessage(`{"command": "rm -rf /"}`),
		},
	}
	responseBody := createAnthropicResponse(content)

	result, err := interceptor.InterceptAnthropicResponse(responseBody, anthropicCtx(types.BlockModeRemove))

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Expected non-nil result")
		return
	}

	// Should pass through unchanged when engine is nil
	if string(result.ModifiedResponse) != string(responseBody) {
		t.Error("Expected response to be unchanged when engine is nil")
	}
}

// TestInterceptAnthropicResponse_EmptyResponse tests empty responses for Anthropic
func TestInterceptAnthropicResponse_EmptyResponse(t *testing.T) {
	interceptor := createTestInterceptor(t, "")

	tests := []struct {
		name         string
		responseBody []byte
	}{
		{
			name:         "empty body",
			responseBody: []byte{},
		},
		{
			name:         "invalid json",
			responseBody: []byte("not json"),
		},
		{
			name:         "empty content",
			responseBody: createAnthropicResponse([]anthropicContentBlock{}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := interceptor.InterceptAnthropicResponse(tt.responseBody, anthropicCtx(types.BlockModeRemove))

			// Should not error
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// Should return original body unchanged for invalid/empty responses
			if string(result.ModifiedResponse) != string(tt.responseBody) {
				t.Errorf("Expected response to be unchanged")
			}
		})
	}
}

// TestInterceptOpenAIResponse_ReplaceModeMessage tests replace mode message formatting
func TestInterceptOpenAIResponse_ReplaceModeMessage(t *testing.T) {
	eventlog.GetMetrics().Reset()

	rulesYAML := `
rules:
  - name: block-rm
    block: "/"
    actions: [delete]
    message: "Security violation detected"
    severity: critical
`
	interceptor := createTestInterceptor(t, rulesYAML)

	responseBody := createOpenAIResponse([]openAIToolCall{makeOAIToolCall("call_1", "Bash", `{"command": "rm -rf /"}`)}, "")
	result, err := interceptor.InterceptOpenAIResponse(responseBody, openaiCtx(types.BlockModeReplace))

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	var parsedResp openAIResponse
	if err := json.Unmarshal(result.ModifiedResponse, &parsedResp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	content := parsedResp.Choices[0].Message.Content
	// In replace mode, should contain Crust message
	if !strings.Contains(content, "[Crust]") {
		t.Errorf("Replace mode content should contain [Crust], got: %s", content)
	}
	if !strings.Contains(content, "Security violation detected") {
		t.Errorf("Replace mode content should contain rule message, got: %s", content)
	}
}

// TestInterceptAnthropicResponse_ReplaceModeMessage tests replace mode for Anthropic
func TestInterceptAnthropicResponse_ReplaceModeMessage(t *testing.T) {
	eventlog.GetMetrics().Reset()

	rulesYAML := `
rules:
  - name: block-rm
    block: "/"
    actions: [delete]
    message: "Security violation detected"
    severity: critical
`
	interceptor := createTestInterceptor(t, rulesYAML)

	content := []anthropicContentBlock{
		{
			Type:  "tool_use",
			ID:    "toolu_1",
			Name:  "Bash",
			Input: json.RawMessage(`{"command": "rm -rf /"}`),
		},
	}
	responseBody := createAnthropicResponse(content)

	result, err := interceptor.InterceptAnthropicResponse(responseBody, anthropicCtx(types.BlockModeReplace))

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	var parsedResp anthropicResponse
	if err := json.Unmarshal(result.ModifiedResponse, &parsedResp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// In replace mode, should have a text block with the replacement message
	hasReplacementText := false
	for _, block := range parsedResp.Content {
		if block.Type == "text" && strings.Contains(block.Text, "[Crust]") {
			hasReplacementText = true
			if !strings.Contains(block.Text, "Security violation detected") {
				t.Errorf("Replacement text should contain rule message, got: %s", block.Text)
			}
		}
	}

	if !hasReplacementText {
		t.Error("Replace mode should add text block with Crust message")
	}

	// Should have no tool_use blocks (was replaced)
	for _, block := range parsedResp.Content {
		if block.Type == "tool_use" {
			t.Error("Replace mode should remove tool_use block")
		}
	}
}

// TestInterceptionResult_Fields tests InterceptionResult field values
func TestInterceptionResult_Fields(t *testing.T) {
	eventlog.GetMetrics().Reset()

	rulesYAML := `
rules:
  - name: block-rm
    block: ["/", "/important", "/important/**"]
    actions: [delete]
    message: "Blocked rm"
    severity: critical
`
	interceptor := createTestInterceptor(t, rulesYAML)

	toolCalls := []openAIToolCall{
		makeOAIToolCall("call_1", "Bash", `{"command": "rm -rf /important"}`),
		makeOAIToolCall("call_2", "Bash", `{"command": "echo hello"}`),
	}
	responseBody := createOpenAIResponse(toolCalls, "")
	result, err := interceptor.InterceptOpenAIResponse(responseBody, openaiCtx(types.BlockModeRemove))

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Check BlockedToolCalls
	if len(result.BlockedToolCalls) != 1 {
		t.Fatalf("Expected 1 blocked call, got %d", len(result.BlockedToolCalls))
	}

	blocked := result.BlockedToolCalls[0]
	if blocked.ToolCall.Name != "Bash" {
		t.Errorf("Blocked tool name = %s, want Bash", blocked.ToolCall.Name)
	}
	if blocked.ToolCall.ID != "call_1" {
		t.Errorf("Blocked tool ID = %s, want call_1", blocked.ToolCall.ID)
	}
	if blocked.MatchResult.RuleName != "block-rm" {
		t.Errorf("MatchResult.RuleName = %s, want block-rm", blocked.MatchResult.RuleName)
	}
	if blocked.MatchResult.Action != rules.ActionBlock {
		t.Errorf("MatchResult.Action = %s, want %s", blocked.MatchResult.Action, rules.ActionBlock)
	}

	// Check AllowedToolCalls
	if len(result.AllowedToolCalls) != 1 {
		t.Fatalf("Expected 1 allowed call, got %d", len(result.AllowedToolCalls))
	}

	allowed := result.AllowedToolCalls[0]
	if allowed.Name != "Bash" {
		t.Errorf("Allowed tool name = %s, want Bash", allowed.Name)
	}
	if allowed.ID != "call_2" {
		t.Errorf("Allowed tool ID = %s, want call_2", allowed.ID)
	}

	if len(result.BlockedToolCalls) == 0 {
		t.Error("BlockedToolCalls should be non-empty")
	}

	// Check ModifiedResponse is not empty
	if len(result.ModifiedResponse) == 0 {
		t.Error("ModifiedResponse should not be empty")
	}
}

// FuzzInterceptAnthropicResponse checks that intercepting Anthropic responses
// never panics and always returns a non-nil result.
// Includes seeds with HTML-special characters as regression tests for the
// json.Marshal HTML-escaping bug (& → \u0026, < → \u003c, > → \u003e).
func FuzzInterceptAnthropicResponse(f *testing.F) {
	// HTML-special character seeds — regression for json.Marshal HTML escaping.
	f.Add(`{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"a & b"}]}`)
	f.Add(`{"id":"msg_2","type":"message","role":"assistant","content":[{"type":"text","text":"<tag>"}]}`)
	f.Add(`{"id":"msg_3","type":"message","role":"assistant","content":[{"type":"text","text":"a > b"}]}`)
	f.Add(`{"id":"msg_4","type":"message","role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"echo a&b"}}]}`)
	// Blocked Bash tool + text with & in same message — exercises re-serialization + HTML escaping invariant.
	f.Add(`{"id":"msg_5","type":"message","role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"ls"}},{"type":"text","text":"running a & b"}]}`)
	// Normal content
	f.Add(`{"id":"msg_6","type":"message","role":"assistant","content":[{"type":"text","text":"hello"}]}`)
	// Edge cases
	f.Add(`{}`)
	f.Add(`[]`)
	f.Add(``)

	// Use a real engine that blocks Bash so tool calls are actually intercepted
	// and re-serialized — making the HTML-escaping invariants non-trivial.
	rulesDir := f.TempDir()
	blockBashYAML := "rules:\n  - name: block-bash\n    match:\n      tool: [Bash]\n    message: \"Bash blocked\"\n"
	if err := os.WriteFile(filepath.Join(rulesDir, "fuzz-rules.yaml"), []byte(blockBashYAML), 0644); err != nil {
		f.Fatalf("Failed to write fuzz rules: %v", err)
	}
	engine, err := rules.NewEngine(context.Background(), rules.EngineConfig{
		UserRulesDir:   rulesDir,
		DisableBuiltin: true,
	})
	if err != nil {
		f.Fatalf("Failed to create engine: %v", err)
	}
	interceptor := NewInterceptor(engine, nil) // nil storage is safe: record.go guards nil

	f.Fuzz(func(t *testing.T, body string) {
		result, err := interceptor.InterceptAnthropicResponse(
			[]byte(body),
			InterceptionContext{
				TraceID:   types.TraceID("fuzz-trace"),
				SessionID: types.SessionID("fuzz-session"),
				Model:     "claude-3",
				APIType:   types.APITypeAnthropic,
				BlockMode: types.BlockModeRemove,
			},
		)
		// INVARIANT 1: Must not panic (implicit — fuzz framework catches panics).

		// INVARIANT 2: result and err must not both be nil.
		if result == nil && err == nil {
			t.Error("both result and err are nil")
		}
		if result != nil && len(result.ModifiedResponse) == 0 && len(body) > 0 {
			t.Errorf("non-empty input produced empty ModifiedResponse: input=%q", body)
		}

		// INVARIANT 3: If the response was re-serialized (output ≠ input), the
		// output must not contain HTML-escaped characters. Regression for the
		// json.Marshal HTML-escaping bug (& → \u0026, < → \u003c, > → \u003e).
		if result != nil && string(result.ModifiedResponse) != body {
			if bytes.Contains(result.ModifiedResponse, []byte(`\u0026`)) {
				t.Errorf("re-serialized output contains HTML-escaped & (\\u0026): %q", result.ModifiedResponse)
			}
			if bytes.Contains(result.ModifiedResponse, []byte(`\u003c`)) {
				t.Errorf("re-serialized output contains HTML-escaped < (\\u003c): %q", result.ModifiedResponse)
			}
			if bytes.Contains(result.ModifiedResponse, []byte(`\u003e`)) {
				t.Errorf("re-serialized output contains HTML-escaped > (\\u003e): %q", result.ModifiedResponse)
			}
		}
	})
}

// --- OpenAI Responses API (InterceptOpenAIResponsesResponse) Tests ---

func responsesCtx(mode types.BlockMode) InterceptionContext {
	return InterceptionContext{
		TraceID: "trace-1", SessionID: "session-1",
		Model: "gpt-4.1", APIType: types.APITypeOpenAIResponses, BlockMode: mode,
	}
}

func TestInterceptOpenAIResponses_BlocksDangerousToolCall(t *testing.T) {
	interceptor := createTestInterceptor(t, credentialAccessRule)
	resp := createOpenAIResponsesResponse([]openAIResponsesOutputItem{
		{Type: "function_call", ID: "fc_1", CallID: "call_1", Name: "Read", Arguments: `{"file_path":"/app/.env"}`},
	})

	result, err := interceptor.InterceptOpenAIResponsesResponse(resp, responsesCtx(types.BlockModeRemove))
	if err != nil {
		t.Fatalf("InterceptOpenAIResponsesResponse: %v", err)
	}
	if len(result.BlockedToolCalls) != 1 {
		t.Fatalf("expected 1 blocked, got %d", len(result.BlockedToolCalls))
	}
	if result.BlockedToolCalls[0].ToolCall.Name != "Read" {
		t.Errorf("blocked tool name: got %q, want %q", result.BlockedToolCalls[0].ToolCall.Name, "Read")
	}
}

func TestInterceptOpenAIResponses_AllowsSafeToolCall(t *testing.T) {
	interceptor := createTestInterceptor(t, credentialAccessRule)
	resp := createOpenAIResponsesResponse([]openAIResponsesOutputItem{
		{Type: "function_call", ID: "fc_1", CallID: "call_1", Name: "Read", Arguments: `{"file_path":"/app/main.go"}`},
	})

	result, err := interceptor.InterceptOpenAIResponsesResponse(resp, responsesCtx(types.BlockModeRemove))
	if err != nil {
		t.Fatalf("InterceptOpenAIResponsesResponse: %v", err)
	}
	if len(result.BlockedToolCalls) != 0 {
		t.Errorf("expected 0 blocked, got %d", len(result.BlockedToolCalls))
	}
	if len(result.AllowedToolCalls) != 1 {
		t.Errorf("expected 1 allowed, got %d", len(result.AllowedToolCalls))
	}
}

func TestInterceptOpenAIResponses_MixedBlockAndAllow(t *testing.T) {
	interceptor := createTestInterceptor(t, credentialAccessRule)
	resp := createOpenAIResponsesResponse([]openAIResponsesOutputItem{
		{Type: "function_call", ID: "fc_1", CallID: "call_1", Name: "Read", Arguments: `{"file_path":"/app/.env"}`},
		{Type: "function_call", ID: "fc_2", CallID: "call_2", Name: "Read", Arguments: `{"file_path":"/app/main.go"}`},
		{Type: "message", ID: "msg_1", Content: []openAIResponsesContent{{Type: "output_text", Text: "Here is the file."}}},
	})

	result, err := interceptor.InterceptOpenAIResponsesResponse(resp, responsesCtx(types.BlockModeRemove))
	if err != nil {
		t.Fatalf("InterceptOpenAIResponsesResponse: %v", err)
	}
	if len(result.BlockedToolCalls) != 1 {
		t.Errorf("expected 1 blocked, got %d", len(result.BlockedToolCalls))
	}
	if len(result.AllowedToolCalls) != 1 {
		t.Errorf("expected 1 allowed, got %d", len(result.AllowedToolCalls))
	}

	// Modified response should not contain the blocked function_call
	var parsed openAIResponsesResponse
	if err := json.Unmarshal(result.ModifiedResponse, &parsed); err != nil {
		t.Fatalf("unmarshal modified response: %v", err)
	}
	for _, item := range parsed.Output {
		if item.Type == "function_call" && item.CallID == "call_1" {
			t.Error("blocked function_call (call_1) should not appear in modified response")
		}
	}
}

func TestInterceptOpenAIResponses_ReplaceMode(t *testing.T) {
	interceptor := createTestInterceptor(t, credentialAccessRule)
	resp := createOpenAIResponsesResponse([]openAIResponsesOutputItem{
		{Type: "function_call", ID: "fc_1", CallID: "call_1", Name: "Read", Arguments: `{"file_path":"/app/.env"}`},
	})

	result, err := interceptor.InterceptOpenAIResponsesResponse(resp, responsesCtx(types.BlockModeReplace))
	if err != nil {
		t.Fatalf("InterceptOpenAIResponsesResponse: %v", err)
	}
	if len(result.BlockedToolCalls) != 1 {
		t.Fatalf("expected 1 blocked, got %d", len(result.BlockedToolCalls))
	}

	// In replace mode, blocked call should be replaced with a message item
	var parsed openAIResponsesResponse
	if err := json.Unmarshal(result.ModifiedResponse, &parsed); err != nil {
		t.Fatalf("unmarshal modified response: %v", err)
	}
	foundReplacement := false
	for _, item := range parsed.Output {
		if item.Type == "function_call" {
			t.Error("blocked function_call should not appear in replace mode")
		}
		if item.Type == "message" && len(item.Content) > 0 {
			foundReplacement = true
		}
	}
	if !foundReplacement {
		t.Error("replace mode should insert a message item for blocked call")
	}
}

func TestInterceptOpenAIResponses_NoToolCalls(t *testing.T) {
	interceptor := createTestInterceptor(t, credentialAccessRule)
	resp := createOpenAIResponsesResponse([]openAIResponsesOutputItem{
		{Type: "message", ID: "msg_1", Content: []openAIResponsesContent{{Type: "output_text", Text: "Hello world"}}},
	})

	result, err := interceptor.InterceptOpenAIResponsesResponse(resp, responsesCtx(types.BlockModeRemove))
	if err != nil {
		t.Fatalf("InterceptOpenAIResponsesResponse: %v", err)
	}
	if len(result.BlockedToolCalls) != 0 {
		t.Errorf("expected 0 blocked, got %d", len(result.BlockedToolCalls))
	}
	if !bytes.Equal(result.ModifiedResponse, resp) {
		t.Error("response with no tool calls should be unchanged")
	}
}

// --- Text-block DLP tests ---

func TestAnthropicTextBlockDLP_SecretRedacted(t *testing.T) {
	interceptor := createTestInterceptor(t, "")
	content := []anthropicContentBlock{
		{Type: "text", Text: "Here is a token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij12"},
	}
	resp := createAnthropicResponse(content)

	result, err := interceptor.InterceptAnthropicResponse(resp, anthropicCtx(types.BlockModeRemove))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed anthropicResponse
	if err := json.Unmarshal(result.ModifiedResponse, &parsed); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(parsed.Content) != 1 {
		t.Fatalf("expected 1 content block, got %d", len(parsed.Content))
	}
	if !strings.Contains(parsed.Content[0].Text, "[REDACTED by Crust:") {
		t.Errorf("expected text to be redacted, got: %s", parsed.Content[0].Text)
	}
}

func TestAnthropicTextBlockDLP_CleanPassThrough(t *testing.T) {
	interceptor := createTestInterceptor(t, "")
	content := []anthropicContentBlock{
		{Type: "text", Text: "This is a perfectly normal message."},
	}
	resp := createAnthropicResponse(content)

	result, err := interceptor.InterceptAnthropicResponse(resp, anthropicCtx(types.BlockModeRemove))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Clean text should pass through unchanged.
	if !bytes.Equal(result.ModifiedResponse, resp) {
		t.Error("clean text response should be unchanged")
	}
}

func TestOpenAIContentDLP_SecretRedacted(t *testing.T) {
	interceptor := createTestInterceptor(t, "")
	resp := createOpenAIResponse(nil, "Here is a token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij12")

	result, err := interceptor.InterceptOpenAIResponse(resp, openaiCtx(types.BlockModeRemove))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed openAIResponse
	if err := json.Unmarshal(result.ModifiedResponse, &parsed); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(parsed.Choices) == 0 {
		t.Fatal("expected at least one choice")
	}
	if !strings.Contains(parsed.Choices[0].Message.Content, "[REDACTED by Crust:") {
		t.Errorf("expected content to be redacted, got: %s", parsed.Choices[0].Message.Content)
	}
}

func TestOpenAIContentDLP_CleanPassThrough(t *testing.T) {
	interceptor := createTestInterceptor(t, "")
	resp := createOpenAIResponse(nil, "This is a perfectly normal message.")

	result, err := interceptor.InterceptOpenAIResponse(resp, openaiCtx(types.BlockModeRemove))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(result.ModifiedResponse, resp) {
		t.Error("clean text response should be unchanged")
	}
}

func TestOpenAIResponsesDLP_SecretRedacted(t *testing.T) {
	interceptor := createTestInterceptor(t, "")
	output := []openAIResponsesOutputItem{
		{
			Type: "message",
			ID:   "msg_1",
			Content: []openAIResponsesContent{
				{Type: "output_text", Text: "Here is a token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij12"},
			},
		},
	}
	resp := createOpenAIResponsesResponse(output)

	result, err := interceptor.InterceptOpenAIResponsesResponse(resp, responsesCtx(types.BlockModeRemove))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed openAIResponsesResponse
	if err := json.Unmarshal(result.ModifiedResponse, &parsed); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(parsed.Output) == 0 || len(parsed.Output[0].Content) == 0 {
		t.Fatal("expected output content")
	}
	if !strings.Contains(parsed.Output[0].Content[0].Text, "[REDACTED by Crust:") {
		t.Errorf("expected output_text to be redacted, got: %s", parsed.Output[0].Content[0].Text)
	}
}

// --- E2E: DLP + tool blocking together, warning text not DLP-scanned ---

// dlpTriggerMessage is a rule message that itself triggers the GitHub token DLP
// pattern (ghp_ + 36 chars). If DLP scans the warning text containing this message,
// the warning will be redacted — exactly the regression we're testing against.
const dlpTriggerMessage = "Blocked ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// TestAnthropicDLP_WarningNotRedacted verifies that Crust's own warning text blocks
// (appended when tool calls are blocked) are never fed through DLP scanning.
// Regression test: with the old (buggy) ordering (DLP after warning append),
// the warning containing dlpTriggerMessage would be redacted. With the fix
// (DLP before warning append), the warning passes through intact.
func TestAnthropicDLP_WarningNotRedacted(t *testing.T) {
	rulesYAML := `
rules:
  - name: block-env
    block: "**/.env"
    actions: [read]
    message: "` + dlpTriggerMessage + `"
    severity: critical
`
	interceptor := createTestInterceptor(t, rulesYAML)

	content := []anthropicContentBlock{
		{Type: "text", Text: "I'll read your config now."},
		{Type: "tool_use", ID: "t1", Name: "read_file", Input: json.RawMessage(`{"path":"/home/user/.env"}`)},
	}
	resp := createAnthropicResponse(content)

	result, err := interceptor.InterceptAnthropicResponse(resp, anthropicCtx(types.BlockModeRemove))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed anthropicResponse
	if err := json.Unmarshal(result.ModifiedResponse, &parsed); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Should have: original text block + warning block (tool_use removed).
	if len(parsed.Content) != 2 {
		t.Fatalf("expected 2 content blocks, got %d", len(parsed.Content))
	}
	// The warning block should NOT be redacted — the DLP-triggering text is
	// in Crust's own warning, which must not be scanned.
	warningBlock := parsed.Content[1]
	if strings.Contains(warningBlock.Text, "[REDACTED by Crust:") {
		t.Errorf("Crust's warning block was incorrectly DLP-scanned and redacted: %s", warningBlock.Text)
	}
	if !strings.Contains(warningBlock.Text, dlpTriggerMessage) {
		t.Errorf("warning should contain the rule message, got: %s", warningBlock.Text)
	}
}

// TestAnthropicDLP_SecretInTextAndBlockedTool verifies both DLP (text redaction)
// and tool blocking work correctly in the same response.
func TestAnthropicDLP_SecretInTextAndBlockedTool(t *testing.T) {
	rulesYAML := `
rules:
  - name: block-env
    block: "**/.env"
    actions: [read]
    message: "Credential file access blocked"
    severity: critical
`
	interceptor := createTestInterceptor(t, rulesYAML)

	content := []anthropicContentBlock{
		{Type: "text", Text: "Here is a token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij12"},
		{Type: "tool_use", ID: "t1", Name: "read_file", Input: json.RawMessage(`{"path":"/home/user/.env"}`)},
	}
	resp := createAnthropicResponse(content)

	result, err := interceptor.InterceptAnthropicResponse(resp, anthropicCtx(types.BlockModeRemove))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed anthropicResponse
	if err := json.Unmarshal(result.ModifiedResponse, &parsed); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(result.BlockedToolCalls) != 1 {
		t.Fatalf("expected 1 blocked tool call, got %d", len(result.BlockedToolCalls))
	}

	// Should have: redacted text block + warning block.
	if len(parsed.Content) != 2 {
		t.Fatalf("expected 2 content blocks, got %d", len(parsed.Content))
	}
	// First block: text should be redacted by DLP.
	if !strings.Contains(parsed.Content[0].Text, "[REDACTED by Crust:") {
		t.Errorf("expected text block to be DLP-redacted, got: %s", parsed.Content[0].Text)
	}
	// Second block: warning should NOT be redacted.
	if strings.Contains(parsed.Content[1].Text, "[REDACTED by Crust:") {
		t.Errorf("warning block should not be DLP-redacted, got: %s", parsed.Content[1].Text)
	}
}

// TestOpenAIDLP_WarningNotRedacted verifies OpenAI Chat path: DLP runs before
// warning text is appended, so the DLP-triggering warning is never scanned.
func TestOpenAIDLP_WarningNotRedacted(t *testing.T) {
	rulesYAML := `
rules:
  - name: block-env
    block: "**/.env"
    actions: [read]
    message: "` + dlpTriggerMessage + `"
    severity: critical
`
	interceptor := createTestInterceptor(t, rulesYAML)

	tc := makeOAIToolCall("t1", "read_file", `{"path":"/home/user/.env"}`)
	resp := createOpenAIResponse([]openAIToolCall{tc}, "")

	result, err := interceptor.InterceptOpenAIResponse(resp, openaiCtx(types.BlockModeRemove))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed openAIResponse
	if err := json.Unmarshal(result.ModifiedResponse, &parsed); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(parsed.Choices) == 0 {
		t.Fatal("expected at least one choice")
	}
	// Warning text should be in content and NOT redacted.
	content := parsed.Choices[0].Message.Content
	if strings.Contains(content, "[REDACTED by Crust:") {
		t.Errorf("Crust's warning was incorrectly DLP-scanned: %s", content)
	}
	if !strings.Contains(content, dlpTriggerMessage) {
		t.Errorf("warning should contain the rule message, got: %s", content)
	}
}

// TestOpenAIResponsesDLP_WarningNotRedacted verifies that warning output_text
// blocks appended by Crust are not fed through DLP. Uses dlpTriggerMessage
// to ensure the test would fail if DLP scanned the warning.
func TestOpenAIResponsesDLP_WarningNotRedacted(t *testing.T) {
	rulesYAML := `
rules:
  - name: block-env
    block: "**/.env"
    actions: [read]
    message: "` + dlpTriggerMessage + `"
    severity: critical
`
	interceptor := createTestInterceptor(t, rulesYAML)

	output := []openAIResponsesOutputItem{
		{
			Type: contentTypeFunctionCall, ID: "fc1", CallID: "call_1",
			Name: "read_file", Arguments: `{"path":"/home/user/.env"}`,
		},
	}
	resp := createOpenAIResponsesResponse(output)

	result, err := interceptor.InterceptOpenAIResponsesResponse(resp, responsesCtx(types.BlockModeRemove))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed openAIResponsesResponse
	if err := json.Unmarshal(result.ModifiedResponse, &parsed); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Should have the warning message item (function_call removed).
	if len(parsed.Output) != 1 {
		t.Fatalf("expected 1 output item, got %d", len(parsed.Output))
	}
	if len(parsed.Output[0].Content) == 0 {
		t.Fatal("expected content in warning output item")
	}
	warningText := parsed.Output[0].Content[0].Text
	if strings.Contains(warningText, "[REDACTED by Crust:") {
		t.Errorf("Crust's warning was incorrectly DLP-scanned: %s", warningText)
	}
	if !strings.Contains(warningText, dlpTriggerMessage) {
		t.Errorf("warning should contain the rule message, got: %s", warningText)
	}
}
