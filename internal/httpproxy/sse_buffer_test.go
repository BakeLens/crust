package httpproxy

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/security"
	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/testutil"
	"github.com/BakeLens/crust/internal/types"
)

func TestBufferedSSEWriter_AnthropicToolUse(t *testing.T) {
	// Create a test response recorder
	w := httptest.NewRecorder()

	// Create buffered writer
	buffer := NewBufferedSSEWriter(w,
		SSEBufferConfig{MaxEvents: 100, Timeout: 30 * time.Second},
		SSERequestContext{TraceID: "trace-1", SessionID: "session-1", Model: "claude-3", APIType: types.APITypeAnthropic, Tools: nil},
	)

	// Simulate Anthropic SSE events for a tool_use
	events := []struct {
		eventType string
		data      string
	}{
		{"message_start", `{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"model":"claude-3-opus-20240229","stop_reason":null,"usage":{"input_tokens":100,"output_tokens":0}}}`},
		{"content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_123","name":"Bash","input":{}}}`},
		{"content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"ls\"}"}}`},
		{"content_block_stop", `{"type":"content_block_stop","index":0}`},
		{"message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":50}}`},
		{"message_stop", `{"type":"message_stop"}`},
	}

	for _, evt := range events {
		raw := []byte("event: " + evt.eventType + "\ndata: " + evt.data + "\n\n")
		err := buffer.BufferEvent(evt.eventType, []byte(evt.data), raw)
		if err != nil {
			t.Fatalf("BufferEvent failed: %v", err)
		}
	}

	// Check tool calls were extracted
	toolCalls := buffer.GetToolCalls()
	if len(toolCalls) != 1 {
		t.Fatalf("Expected 1 tool call, got %d", len(toolCalls))
	}

	if toolCalls[0].Name != "Bash" {
		t.Errorf("Expected tool name 'Bash', got '%s'", toolCalls[0].Name)
	}

	if toolCalls[0].ID != "toolu_123" {
		t.Errorf("Expected tool ID 'toolu_123', got '%s'", toolCalls[0].ID)
	}

	var args map[string]string
	if err := json.Unmarshal(toolCalls[0].Arguments, &args); err != nil {
		t.Fatalf("Failed to unmarshal arguments: %v", err)
	}
	if args["command"] != "ls" {
		t.Errorf("Expected command 'ls', got '%s'", args["command"])
	}
}

func TestBufferedSSEWriter_OpenAIToolUse(t *testing.T) {
	w := httptest.NewRecorder()
	buffer := NewBufferedSSEWriter(w,
		SSEBufferConfig{MaxEvents: 100, Timeout: 30 * time.Second},
		SSERequestContext{TraceID: "trace-1", SessionID: "session-1", Model: "gpt-4", APIType: types.APITypeOpenAICompletion, Tools: nil},
	)

	// Simulate OpenAI SSE events for a tool call
	events := []struct {
		data string
	}{
		{`{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4","choices":[{"index":0,"delta":{"role":"assistant","content":null,"tool_calls":[{"index":0,"id":"call_abc","function":{"name":"get_weather","arguments":""}}]},"finish_reason":null}]}`},
		{`{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"location\":"}}]},"finish_reason":null}]}`},
		{`{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"NYC\"}"}}]},"finish_reason":null}]}`},
		{`{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`},
		{`[DONE]`},
	}

	for _, evt := range events {
		raw := []byte("data: " + evt.data + "\n\n")
		err := buffer.BufferEvent("", []byte(evt.data), raw)
		if err != nil {
			t.Fatalf("BufferEvent failed: %v", err)
		}
	}

	toolCalls := buffer.GetToolCalls()
	if len(toolCalls) != 1 {
		t.Fatalf("Expected 1 tool call, got %d", len(toolCalls))
	}

	if toolCalls[0].Name != "get_weather" {
		t.Errorf("Expected tool name 'get_weather', got '%s'", toolCalls[0].Name)
	}

	if toolCalls[0].ID != "call_abc" {
		t.Errorf("Expected tool ID 'call_abc', got '%s'", toolCalls[0].ID)
	}
}

func TestBufferedSSEWriter_FlushAll(t *testing.T) {
	w := httptest.NewRecorder()
	buffer := NewBufferedSSEWriter(w,
		SSEBufferConfig{MaxEvents: 100, Timeout: 30 * time.Second},
		SSERequestContext{TraceID: "trace-1", SessionID: "session-1", Model: "claude-3", APIType: types.APITypeAnthropic, Tools: nil},
	)

	// Add some events
	event1 := []byte("data: {\"type\":\"message_start\"}\n\n")
	event2 := []byte("data: {\"type\":\"message_stop\"}\n\n")

	_ = buffer.BufferEvent("message_start", []byte(`{"type":"message_start"}`), event1)
	_ = buffer.BufferEvent("message_stop", []byte(`{"type":"message_stop"}`), event2)

	// Flush all
	err := buffer.FlushAll()
	if err != nil {
		t.Fatalf("FlushAll failed: %v", err)
	}

	// Check output
	body := w.Body.String()
	if !strings.Contains(body, "message_start") {
		t.Error("Expected output to contain message_start")
	}
	if !strings.Contains(body, "message_stop") {
		t.Error("Expected output to contain message_stop")
	}
}

func TestBufferedSSEWriter_BufferSizeLimit(t *testing.T) {
	w := httptest.NewRecorder()
	buffer := NewBufferedSSEWriter(w,
		SSEBufferConfig{MaxEvents: 2, Timeout: 30 * time.Second},
		SSERequestContext{TraceID: "trace-1", SessionID: "session-1", Model: "claude-3", APIType: types.APITypeAnthropic, Tools: nil},
	)

	// Add events up to limit
	_ = buffer.BufferEvent("event1", []byte("{}"), []byte("data: {}\n\n"))
	_ = buffer.BufferEvent("event2", []byte("{}"), []byte("data: {}\n\n"))

	// Third event should fail
	err := buffer.BufferEvent("event3", []byte("{}"), []byte("data: {}\n\n"))
	if err == nil {
		t.Error("Expected error when buffer size exceeded")
	}
}

func TestBufferedSSEWriter_Timeout(t *testing.T) {
	w := httptest.NewRecorder()
	buffer := NewBufferedSSEWriter(w,
		SSEBufferConfig{MaxEvents: 100, Timeout: 1 * time.Millisecond},
		SSERequestContext{TraceID: "trace-1", SessionID: "session-1", Model: "claude-3", APIType: types.APITypeAnthropic, Tools: nil},
	)

	// Buffer one event before the timeout fires.
	_ = buffer.BufferEvent("message_start", []byte(`{}`), []byte("data: {}\n\n"))

	time.Sleep(10 * time.Millisecond) // ensure timeout elapsed

	// BufferEvent must return a timeout error.
	err := buffer.BufferEvent("event", []byte("{}"), []byte("data: {}\n\n"))
	if err == nil {
		t.Fatal("expected error when buffer timed out, got nil")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Errorf("error should mention timeout, got: %v", err)
	}

	// After a timeout error, FlushModified and FlushAll must return nil and must
	// write no events to the client (fail-closed: timed-out buffer is discarded).
	bytesBefore := w.Body.Len()
	if ferr := buffer.FlushModified(nil, types.BlockModeRemove); ferr != nil {
		t.Errorf("FlushModified after timeout returned %v, want nil", ferr)
	}
	if ferr := buffer.FlushAll(); ferr != nil {
		t.Errorf("FlushAll after timeout returned %v, want nil", ferr)
	}
	if w.Body.Len() != bytesBefore {
		t.Errorf("flush after timeout wrote %d bytes, want 0 (fail-closed)", w.Body.Len()-bytesBefore)
	}
}

func TestBuildBlockedReplacement_WithMessage(t *testing.T) {
	result := buildBlockedReplacement("Bash", rules.MatchResult{
		Message: "Dangerous command",
	})

	if result["command"] == "" {
		t.Fatal("command should not be empty")
	}
	if !strings.Contains(result["command"], "Bash") || !strings.Contains(result["command"], "Dangerous command") {
		t.Errorf("command = %q, want blocked message with tool name and reason", result["command"])
	}
	if !strings.Contains(result["command"], "Do not retry") {
		t.Error("command should contain 'Do not retry'")
	}
	if result["description"] != "Security: blocked tool call" {
		t.Errorf("description = %q, want %q", result["description"], "Security: blocked tool call")
	}
}

func TestBuildBlockedReplacement_WithoutMessage(t *testing.T) {
	result := buildBlockedReplacement("Read", rules.MatchResult{})

	if !strings.Contains(result["command"], "Read") || !strings.Contains(result["command"], "blocked") {
		t.Errorf("command = %q, want blocked message with tool name", result["command"])
	}
	if !strings.Contains(result["command"], "Do not retry") {
		t.Error("command should contain 'Do not retry'")
	}
}

func TestBufferedSSEWriter_ReplaceModeNoShellTool_FallsBackToRemove(t *testing.T) {
	w := httptest.NewRecorder()
	// Create buffer with NO shell tool (only non-shell tools)
	tools := []AvailableTool{
		{Name: "Read", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}
	buffer := NewBufferedSSEWriter(w,
		SSEBufferConfig{MaxEvents: 100, Timeout: 30 * time.Second},
		SSERequestContext{TraceID: "trace-1", SessionID: "session-1", Model: "claude-3", APIType: types.APITypeAnthropic, Tools: tools},
	)

	// Buffer Anthropic events with a tool_use
	events := []struct {
		eventType string
		data      string
	}{
		{"message_start", `{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"model":"claude-3","usage":{"input_tokens":10,"output_tokens":0}}}`},
		{"content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"Write","input":{}}}`},
		{"content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"path\":\"/etc/passwd\"}"}}`},
		{"content_block_stop", `{"type":"content_block_stop","index":0}`},
		{"message_delta", `{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":10}}`},
		{"message_stop", `{"type":"message_stop"}`},
	}

	for _, evt := range events {
		raw := []byte("event: " + evt.eventType + "\ndata: " + evt.data + "\n\n")
		if err := buffer.BufferEvent(evt.eventType, []byte(evt.data), raw); err != nil {
			t.Fatalf("BufferEvent failed: %v", err)
		}
	}

	// FlushAll to verify no panic with replace mode and no shell tool
	if err := buffer.FlushAll(); err != nil {
		t.Fatalf("FlushAll failed: %v", err)
	}

	body := w.Body.String()
	if !strings.Contains(body, "message_start") {
		t.Error("message_start event should be present")
	}
}

// =============================================================================
// Helper: create interceptor for SSE buffer tests
// =============================================================================

func newTestInterceptor(t *testing.T) *security.Interceptor {
	t.Helper()
	engine := testutil.NewEngine(t)
	storage, err := telemetry.NewStorage(":memory:", "")
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	t.Cleanup(func() { storage.Close() })
	return security.NewInterceptor(engine, storage)
}

// =============================================================================
// Anthropic: FlushModified remove mode — blocked tool call events stripped,
// warning injected before message_stop
// =============================================================================

func TestFlushModified_Anthropic_RemoveMode(t *testing.T) {
	interceptor := newTestInterceptor(t)
	w := httptest.NewRecorder()
	buffer := NewBufferedSSEWriter(w,
		SSEBufferConfig{MaxEvents: 100, Timeout: 30 * time.Second},
		SSERequestContext{
			TraceID: "t1", SessionID: "s1", Model: "claude-3",
			APIType: types.APITypeAnthropic,
			Tools:   []AvailableTool{{Name: "Bash"}},
		},
	)

	// Tool call reading /etc/shadow (blocked by builtin rules)
	events := []struct {
		eventType string
		data      string
	}{
		{"message_start", `{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"model":"claude-3","usage":{"input_tokens":10,"output_tokens":0}}}`},
		{"content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"Bash","input":{}}}`},
		{"content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"cat /etc/shadow\"}"}}`},
		{"content_block_stop", `{"type":"content_block_stop","index":0}`},
		{"message_delta", `{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":10}}`},
		{"message_stop", `{"type":"message_stop"}`},
	}
	for _, evt := range events {
		raw := []byte("event: " + evt.eventType + "\ndata: " + evt.data + "\n\n")
		if err := buffer.BufferEvent(evt.eventType, []byte(evt.data), raw); err != nil {
			t.Fatalf("BufferEvent: %v", err)
		}
	}

	if err := buffer.FlushModified(interceptor, types.BlockModeRemove); err != nil {
		t.Fatalf("FlushModified: %v", err)
	}

	body := w.Body.String()

	// Blocked tool_use content blocks must be stripped
	if strings.Contains(body, `"name":"Bash"`) && strings.Contains(body, "cat /etc/shadow") {
		t.Error("blocked tool_use events should have been removed")
	}

	// Warning must be injected (content block at index 999)
	if !strings.Contains(body, "999") {
		t.Error("warning block (index 999) should be injected")
	}
	if !strings.Contains(body, "blocked") || !strings.Contains(body, "Crust") {
		t.Error("warning text should mention blocking by Crust")
	}

	// message_start and message_stop must still be present
	if !strings.Contains(body, "message_start") {
		t.Error("message_start should be present")
	}
	if !strings.Contains(body, "message_stop") {
		t.Error("message_stop should be present")
	}
}

// =============================================================================
// Anthropic: FlushModified replace mode — blocked tool call replaced with
// echo command via shell tool
// =============================================================================

func TestFlushModified_Anthropic_ReplaceMode(t *testing.T) {
	interceptor := newTestInterceptor(t)
	w := httptest.NewRecorder()
	buffer := NewBufferedSSEWriter(w,
		SSEBufferConfig{MaxEvents: 100, Timeout: 30 * time.Second},
		SSERequestContext{
			TraceID: "t1", SessionID: "s1", Model: "claude-3",
			APIType: types.APITypeAnthropic,
			Tools: []AvailableTool{
				{Name: "Bash"},
				{Name: "Read"},
			},
		},
	)

	// Read tool trying to access SSH private key (blocked)
	events := []struct {
		eventType string
		data      string
	}{
		{"message_start", `{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"model":"claude-3","usage":{"input_tokens":10,"output_tokens":0}}}`},
		{"content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"Read","input":{}}}`},
		{"content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"file_path\":\"/home/user/.ssh/id_rsa\"}"}}`},
		{"content_block_stop", `{"type":"content_block_stop","index":0}`},
		{"message_delta", `{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":10}}`},
		{"message_stop", `{"type":"message_stop"}`},
	}
	for _, evt := range events {
		raw := []byte("event: " + evt.eventType + "\ndata: " + evt.data + "\n\n")
		if err := buffer.BufferEvent(evt.eventType, []byte(evt.data), raw); err != nil {
			t.Fatalf("BufferEvent: %v", err)
		}
	}

	if err := buffer.FlushModified(interceptor, types.BlockModeReplace); err != nil {
		t.Fatalf("FlushModified: %v", err)
	}

	body := w.Body.String()

	// Original Read tool_use should be replaced with Bash
	if strings.Contains(body, `"name":"Read"`) {
		t.Error("original Read tool should have been replaced")
	}
	if !strings.Contains(body, `"name":"Bash"`) {
		t.Error("replacement should use Bash tool")
	}

	// Replacement should contain an echo command with block message
	if !strings.Contains(body, "echo") {
		t.Error("replacement should contain an echo command")
	}
	if !strings.Contains(body, "blocked") {
		t.Error("replacement should mention 'blocked'")
	}
}

// =============================================================================
// OpenAI Completion: FlushModified remove mode — blocked tool calls removed
// from delta chunks, warning injected before [DONE]
// =============================================================================

func TestFlushModified_OpenAI_RemoveMode(t *testing.T) {
	interceptor := newTestInterceptor(t)
	w := httptest.NewRecorder()
	buffer := NewBufferedSSEWriter(w,
		SSEBufferConfig{MaxEvents: 100, Timeout: 30 * time.Second},
		SSERequestContext{
			TraceID: "t1", SessionID: "s1", Model: "gpt-4",
			APIType: types.APITypeOpenAICompletion,
			Tools:   []AvailableTool{{Name: "Bash"}},
		},
	)

	// OpenAI streaming tool call reading /etc/shadow
	events := []struct {
		data string
	}{
		{`{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4","choices":[{"index":0,"delta":{"role":"assistant","content":null,"tool_calls":[{"index":0,"id":"call_1","function":{"name":"Bash","arguments":""}}]},"finish_reason":null}]}`},
		{`{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"command\":\"cat /etc/shadow\"}"}}]},"finish_reason":null}]}`},
		{`{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`},
		{`[DONE]`},
	}
	for _, evt := range events {
		raw := []byte("data: " + evt.data + "\n\n")
		if err := buffer.BufferEvent("", []byte(evt.data), raw); err != nil {
			t.Fatalf("BufferEvent: %v", err)
		}
	}

	if err := buffer.FlushModified(interceptor, types.BlockModeRemove); err != nil {
		t.Fatalf("FlushModified: %v", err)
	}

	body := w.Body.String()

	// Tool call should be removed from chunks
	if strings.Contains(body, "cat /etc/shadow") {
		t.Error("blocked tool call arguments should be removed")
	}

	// Warning chunk should be injected
	if !strings.Contains(body, "security-warning") {
		t.Error("security warning chunk should be injected")
	}

	// [DONE] should still be present
	if !strings.Contains(body, "[DONE]") {
		t.Error("[DONE] marker should be present")
	}
}

// =============================================================================
// OpenAI Completion: FlushModified replace mode — blocked tool call replaced
// with shell echo command
// =============================================================================

func TestFlushModified_OpenAI_ReplaceMode(t *testing.T) {
	interceptor := newTestInterceptor(t)
	w := httptest.NewRecorder()
	buffer := NewBufferedSSEWriter(w,
		SSEBufferConfig{MaxEvents: 100, Timeout: 30 * time.Second},
		SSERequestContext{
			TraceID: "t1", SessionID: "s1", Model: "gpt-4",
			APIType: types.APITypeOpenAICompletion,
			Tools: []AvailableTool{
				{Name: "Bash"},
				{Name: "Read"},
			},
		},
	)

	events := []struct {
		data string
	}{
		{`{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4","choices":[{"index":0,"delta":{"role":"assistant","content":null,"tool_calls":[{"index":0,"id":"call_1","function":{"name":"Read","arguments":""}}]},"finish_reason":null}]}`},
		{`{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"file_path\":\"/home/user/.ssh/id_rsa\"}"}}]},"finish_reason":null}]}`},
		{`{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`},
		{`[DONE]`},
	}
	for _, evt := range events {
		raw := []byte("data: " + evt.data + "\n\n")
		if err := buffer.BufferEvent("", []byte(evt.data), raw); err != nil {
			t.Fatalf("BufferEvent: %v", err)
		}
	}

	if err := buffer.FlushModified(interceptor, types.BlockModeReplace); err != nil {
		t.Fatalf("FlushModified: %v", err)
	}

	body := w.Body.String()

	// Replaced tool call should use Bash name
	if !strings.Contains(body, `"name":"Bash"`) {
		t.Error("replacement should use Bash tool name")
	}
	// Should contain echo command
	if !strings.Contains(body, "echo") {
		t.Error("replacement should contain echo command")
	}
	// Original tool name should not appear as function name
	if strings.Contains(body, `"name":"Read"`) {
		t.Error("original Read tool name should be replaced")
	}
}

// =============================================================================
// OpenAI Responses: FlushModified remove mode — blocked function_call events
// stripped, warning injected before response.completed
// =============================================================================

func TestFlushModified_OpenAIResponses_RemoveMode(t *testing.T) {
	interceptor := newTestInterceptor(t)
	w := httptest.NewRecorder()
	buffer := NewBufferedSSEWriter(w,
		SSEBufferConfig{MaxEvents: 100, Timeout: 30 * time.Second},
		SSERequestContext{
			TraceID: "t1", SessionID: "s1", Model: "gpt-4",
			APIType: types.APITypeOpenAIResponses,
			Tools:   []AvailableTool{{Name: "Bash"}},
		},
	)

	// OpenAI Responses API events
	events := []struct {
		eventType string
		data      string
	}{
		{sseResponseOutputItemAdded, `{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","call_id":"call_1","name":"Bash","id":"call_1"}}`},
		{sseResponseFunctionCallArgumentsDelta, `{"type":"response.function_call_arguments.delta","output_index":0,"delta":"{\"command\":\"cat /etc/shadow\"}"}`},
		{sseResponseFunctionCallArgumentsDone, `{"type":"response.function_call_arguments.done","output_index":0,"arguments":"{\"command\":\"cat /etc/shadow\"}"}`},
		{sseResponseOutputItemDone, `{"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","call_id":"call_1","name":"Bash","id":"call_1","arguments":"{\"command\":\"cat /etc/shadow\"}"}}`},
		{sseResponseCompleted, `{"type":"response.completed","response":{"id":"resp_1","status":"completed"}}`},
	}
	for _, evt := range events {
		raw := []byte("event: " + evt.eventType + "\ndata: " + evt.data + "\n\n")
		if err := buffer.BufferEvent(evt.eventType, []byte(evt.data), raw); err != nil {
			t.Fatalf("BufferEvent: %v", err)
		}
	}

	if err := buffer.FlushModified(interceptor, types.BlockModeRemove); err != nil {
		t.Fatalf("FlushModified: %v", err)
	}

	body := w.Body.String()

	// Blocked events with output_index 0 should be stripped
	if strings.Contains(body, "cat /etc/shadow") {
		t.Error("blocked function call arguments should be removed")
	}

	// Warning should be injected (output_index 999)
	if !strings.Contains(body, "999") {
		t.Error("warning event (output_index 999) should be injected")
	}

	// response.completed should still be present
	if !strings.Contains(body, sseResponseCompleted) {
		t.Error("response.completed should be present")
	}
}

// =============================================================================
// OpenAI Responses: FlushModified replace mode — blocked function_call
// replaced with shell echo command
// =============================================================================

func TestFlushModified_OpenAIResponses_ReplaceMode(t *testing.T) {
	interceptor := newTestInterceptor(t)
	w := httptest.NewRecorder()
	buffer := NewBufferedSSEWriter(w,
		SSEBufferConfig{MaxEvents: 100, Timeout: 30 * time.Second},
		SSERequestContext{
			TraceID: "t1", SessionID: "s1", Model: "gpt-4",
			APIType: types.APITypeOpenAIResponses,
			Tools: []AvailableTool{
				{Name: "Bash"},
				{Name: "Read"},
			},
		},
	)

	events := []struct {
		eventType string
		data      string
	}{
		{sseResponseOutputItemAdded, `{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","call_id":"call_1","name":"Read","id":"call_1"}}`},
		{sseResponseFunctionCallArgumentsDelta, `{"type":"response.function_call_arguments.delta","output_index":0,"delta":"{\"file_path\":\"/home/user/.ssh/id_rsa\"}"}`},
		{sseResponseFunctionCallArgumentsDone, `{"type":"response.function_call_arguments.done","output_index":0,"arguments":"{\"file_path\":\"/home/user/.ssh/id_rsa\"}"}`},
		{sseResponseOutputItemDone, `{"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","call_id":"call_1","name":"Read","id":"call_1","arguments":"{\"file_path\":\"/home/user/.ssh/id_rsa\"}"}}`},
		{sseResponseCompleted, `{"type":"response.completed","response":{"id":"resp_1","status":"completed"}}`},
	}
	for _, evt := range events {
		raw := []byte("event: " + evt.eventType + "\ndata: " + evt.data + "\n\n")
		if err := buffer.BufferEvent(evt.eventType, []byte(evt.data), raw); err != nil {
			t.Fatalf("BufferEvent: %v", err)
		}
	}

	if err := buffer.FlushModified(interceptor, types.BlockModeReplace); err != nil {
		t.Fatalf("FlushModified: %v", err)
	}

	body := w.Body.String()

	// Replaced item should use Bash tool
	if !strings.Contains(body, `"name":"Bash"`) {
		t.Error("replacement should use Bash tool name")
	}
	if !strings.Contains(body, "echo") {
		t.Error("replacement should contain echo command")
	}
	// Original tool name should not appear in function call events
	if strings.Contains(body, `"name":"Read"`) {
		t.Error("original Read tool name should be replaced")
	}
}

// =============================================================================
// findShellTool: verify priority order and not-found case
// =============================================================================

func TestFindShellTool(t *testing.T) {
	tests := []struct {
		name      string
		tools     []AvailableTool
		wantName  string
		wantFound bool
	}{
		{
			name:      "Bash tool present",
			tools:     []AvailableTool{{Name: "Bash"}, {Name: "Read"}},
			wantName:  "Bash",
			wantFound: true,
		},
		{
			name:      "shell tool present",
			tools:     []AvailableTool{{Name: "Read"}, {Name: "shell"}},
			wantName:  "shell",
			wantFound: true,
		},
		{
			name:      "Terminal tool present",
			tools:     []AvailableTool{{Name: "Terminal"}},
			wantName:  "Terminal",
			wantFound: true,
		},
		{
			name:      "no shell tool",
			tools:     []AvailableTool{{Name: "Read"}, {Name: "Write"}},
			wantName:  "",
			wantFound: false,
		},
		{
			name:      "priority order: Bash before shell",
			tools:     []AvailableTool{{Name: "shell"}, {Name: "Bash"}},
			wantName:  "Bash",
			wantFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			buffer := NewBufferedSSEWriter(w,
				SSEBufferConfig{MaxEvents: 10, Timeout: time.Second},
				SSERequestContext{APIType: types.APITypeAnthropic, Tools: tt.tools},
			)
			name, found := buffer.findShellTool()
			if found != tt.wantFound {
				t.Errorf("found = %v, want %v", found, tt.wantFound)
			}
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
		})
	}
}

// =============================================================================
// marshalJSON: verify no HTML escaping
// =============================================================================

func TestMarshalJSON_NoHTMLEscape(t *testing.T) {
	data := map[string]string{"msg": "a < b & c > d"}
	got, err := marshalJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got, []byte(`\u003c`)) || bytes.Contains(got, []byte(`\u0026`)) || bytes.Contains(got, []byte(`\u003e`)) {
		t.Errorf("marshalJSON should not HTML-escape: %s", got)
	}
	if !bytes.Contains(got, []byte(`<`)) || !bytes.Contains(got, []byte(`&`)) || !bytes.Contains(got, []byte(`>`)) {
		t.Errorf("marshalJSON should preserve <, &, >: %s", got)
	}
	// Should not have trailing newline
	if bytes.HasSuffix(got, []byte("\n")) {
		t.Error("marshalJSON should strip trailing newline")
	}
}

// =============================================================================
// writeSSEEvent / writeSSEData / writeRaw: verify framing
// =============================================================================

func TestWriteSSEEvent_Framing(t *testing.T) {
	w := httptest.NewRecorder()
	buffer := NewBufferedSSEWriter(w,
		SSEBufferConfig{MaxEvents: 10, Timeout: time.Second},
		SSERequestContext{APIType: types.APITypeAnthropic},
	)

	data := map[string]string{"key": "value"}
	if err := buffer.writeSSEEvent("test_event", data); err != nil {
		t.Fatal(err)
	}

	body := w.Body.String()
	if !strings.HasPrefix(body, "event: test_event\ndata: ") {
		t.Errorf("wrong SSE framing: %q", body)
	}
	if !strings.HasSuffix(body, "\n\n") {
		t.Errorf("SSE event should end with double newline: %q", body)
	}
	if !strings.Contains(body, `"key":"value"`) {
		t.Errorf("SSE event should contain JSON data: %q", body)
	}
}

func TestWriteSSEData_Framing(t *testing.T) {
	w := httptest.NewRecorder()
	buffer := NewBufferedSSEWriter(w,
		SSEBufferConfig{MaxEvents: 10, Timeout: time.Second},
		SSERequestContext{APIType: types.APITypeOpenAICompletion},
	)

	data := map[string]int{"count": 42}
	if err := buffer.writeSSEData(data); err != nil {
		t.Fatal(err)
	}

	body := w.Body.String()
	if !strings.HasPrefix(body, "data: ") {
		t.Errorf("writeSSEData should have 'data: ' prefix: %q", body)
	}
	if !strings.HasSuffix(body, "\n\n") {
		t.Errorf("writeSSEData should end with double newline: %q", body)
	}
	// Should NOT have "event:" line
	if strings.Contains(body, "event:") {
		t.Errorf("writeSSEData should not have event line: %q", body)
	}
}

func TestWriteRaw(t *testing.T) {
	w := httptest.NewRecorder()
	buffer := NewBufferedSSEWriter(w,
		SSEBufferConfig{MaxEvents: 10, Timeout: time.Second},
		SSERequestContext{APIType: types.APITypeAnthropic},
	)

	raw := []byte("event: test\ndata: hello\n\n")
	if err := buffer.writeRaw(raw); err != nil {
		t.Fatal(err)
	}
	if w.Body.String() != string(raw) {
		t.Errorf("writeRaw should write exact bytes, got %q", w.Body.String())
	}
}

// =============================================================================
// FlushModified with no tool use should flush as-is
// =============================================================================

func TestFlushModified_NoToolUse_FlushesAsIs(t *testing.T) {
	interceptor := newTestInterceptor(t)
	w := httptest.NewRecorder()
	buffer := NewBufferedSSEWriter(w,
		SSEBufferConfig{MaxEvents: 100, Timeout: 30 * time.Second},
		SSERequestContext{
			TraceID: "t1", SessionID: "s1", Model: "claude-3",
			APIType: types.APITypeAnthropic,
			Tools:   []AvailableTool{{Name: "Bash"}},
		},
	)

	// Text-only response (no tool use)
	events := []struct {
		eventType string
		data      string
	}{
		{"message_start", `{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"model":"claude-3","usage":{"input_tokens":10,"output_tokens":0}}}`},
		{"content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`},
		{"content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello!"}}`},
		{"content_block_stop", `{"type":"content_block_stop","index":0}`},
		{"message_stop", `{"type":"message_stop"}`},
	}
	for _, evt := range events {
		raw := []byte("event: " + evt.eventType + "\ndata: " + evt.data + "\n\n")
		if err := buffer.BufferEvent(evt.eventType, []byte(evt.data), raw); err != nil {
			t.Fatalf("BufferEvent: %v", err)
		}
	}

	if err := buffer.FlushModified(interceptor, types.BlockModeRemove); err != nil {
		t.Fatalf("FlushModified: %v", err)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Hello!") {
		t.Error("text content should be flushed as-is")
	}
	// No warning should be injected
	if strings.Contains(body, "999") {
		t.Error("no warning block should be injected for text-only response")
	}
}

// =============================================================================
// FlushModified with allowed tool call should flush as-is
// =============================================================================

func TestFlushModified_AllowedToolCall_FlushesAsIs(t *testing.T) {
	interceptor := newTestInterceptor(t)
	w := httptest.NewRecorder()
	buffer := NewBufferedSSEWriter(w,
		SSEBufferConfig{MaxEvents: 100, Timeout: 30 * time.Second},
		SSERequestContext{
			TraceID: "t1", SessionID: "s1", Model: "claude-3",
			APIType: types.APITypeAnthropic,
			Tools:   []AvailableTool{{Name: "Bash"}},
		},
	)

	// Safe tool call (ls is allowed)
	events := []struct {
		eventType string
		data      string
	}{
		{"message_start", `{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"model":"claude-3","usage":{"input_tokens":10,"output_tokens":0}}}`},
		{"content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"Bash","input":{}}}`},
		{"content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"ls /tmp\"}"}}`},
		{"content_block_stop", `{"type":"content_block_stop","index":0}`},
		{"message_stop", `{"type":"message_stop"}`},
	}
	for _, evt := range events {
		raw := []byte("event: " + evt.eventType + "\ndata: " + evt.data + "\n\n")
		if err := buffer.BufferEvent(evt.eventType, []byte(evt.data), raw); err != nil {
			t.Fatalf("BufferEvent: %v", err)
		}
	}

	if err := buffer.FlushModified(interceptor, types.BlockModeRemove); err != nil {
		t.Fatalf("FlushModified: %v", err)
	}

	body := w.Body.String()
	if !strings.Contains(body, "ls /tmp") {
		t.Error("allowed tool call should be flushed as-is")
	}
	if strings.Contains(body, "999") {
		t.Error("no warning should be injected for allowed tool calls")
	}
}
