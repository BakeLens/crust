package httpproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/types"
)

func TestSSEReader_AnthropicToolUse(t *testing.T) {
	// Simulate Anthropic SSE stream with tool_use
	sseStream := `event: message_start
data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"model":"claude-3-opus-20240229","stop_reason":null,"usage":{"input_tokens":100,"output_tokens":0}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_abc","name":"Bash","input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":"}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"\"echo hello\"}"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":50}}

event: message_stop
data: {"type":"message_stop"}

`

	body := io.NopCloser(bytes.NewReader([]byte(sseStream)))

	var capturedToolCalls []telemetry.ToolCall
	var capturedInput, capturedOutput int64

	reader := NewSSEReaderWithSecurity(body, types.APITypeAnthropic, "trace-1", "session-1", "claude-3", nil, func(in, out int64, content string, toolCalls []telemetry.ToolCall) {
		capturedInput = in
		capturedOutput = out
		capturedToolCalls = toolCalls
	})

	// Read all data
	buf := make([]byte, 4096)
	for {
		_, err := reader.Read(buf)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Read error: %v", err)
		}
	}

	// Close to trigger completion
	_ = reader.Close()

	// Check token usage
	if capturedInput != 100 {
		t.Errorf("Expected input tokens 100, got %d", capturedInput)
	}
	if capturedOutput != 50 {
		t.Errorf("Expected output tokens 50, got %d", capturedOutput)
	}

	// Check tool calls
	if len(capturedToolCalls) != 1 {
		t.Fatalf("Expected 1 tool call, got %d", len(capturedToolCalls))
	}

	tc := capturedToolCalls[0]
	if tc.Name != "Bash" {
		t.Errorf("Expected tool name 'Bash', got '%s'", tc.Name)
	}
	if tc.ID != "toolu_abc" {
		t.Errorf("Expected tool ID 'toolu_abc', got '%s'", tc.ID)
	}

	var args map[string]string
	if err := json.Unmarshal(tc.Arguments, &args); err != nil {
		t.Fatalf("Failed to unmarshal arguments: %v", err)
	}
	if args["command"] != "echo hello" {
		t.Errorf("Expected command 'echo hello', got '%s'", args["command"])
	}
}

func TestSSEReader_AnthropicTextContent(t *testing.T) {
	// Simulate Anthropic SSE stream with text content
	sseStream := `event: message_start
data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"model":"claude-3-opus-20240229","stop_reason":null,"usage":{"input_tokens":50,"output_tokens":0}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":" World"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":10}}

event: message_stop
data: {"type":"message_stop"}

`

	body := io.NopCloser(bytes.NewReader([]byte(sseStream)))

	var capturedContent string
	var capturedToolCalls []telemetry.ToolCall

	reader := NewSSEReaderWithSecurity(body, types.APITypeAnthropic, "trace-1", "session-1", "claude-3", nil, func(in, out int64, content string, toolCalls []telemetry.ToolCall) {
		capturedContent = content
		capturedToolCalls = toolCalls
	})

	buf := make([]byte, 4096)
	for {
		_, err := reader.Read(buf)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Read error: %v", err)
		}
	}
	_ = reader.Close()

	if capturedContent != "Hello World" {
		t.Errorf("Expected content 'Hello World', got '%s'", capturedContent)
	}

	if len(capturedToolCalls) != 0 {
		t.Errorf("Expected 0 tool calls, got %d", len(capturedToolCalls))
	}
}

func TestSSEReader_OpenAIToolUse(t *testing.T) {
	// Simulate OpenAI SSE stream with tool calls
	sseStream := `data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4","choices":[{"index":0,"delta":{"role":"assistant","content":null,"tool_calls":[{"index":0,"id":"call_xyz","function":{"name":"get_weather","arguments":""}}]},"finish_reason":null}]}

data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"location\":"}}]},"finish_reason":null}]}

data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"Paris\"}"}}]},"finish_reason":null}]}

data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":25,"completion_tokens":15}}

data: [DONE]

`

	body := io.NopCloser(bytes.NewReader([]byte(sseStream)))

	var capturedToolCalls []telemetry.ToolCall

	reader := NewSSEReaderWithSecurity(body, types.APITypeOpenAICompletion, "trace-1", "session-1", "gpt-4", nil, func(in, out int64, content string, toolCalls []telemetry.ToolCall) {
		capturedToolCalls = toolCalls
	})

	buf := make([]byte, 4096)
	for {
		_, err := reader.Read(buf)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Read error: %v", err)
		}
	}
	_ = reader.Close()

	if len(capturedToolCalls) != 1 {
		t.Fatalf("Expected 1 tool call, got %d", len(capturedToolCalls))
	}

	tc := capturedToolCalls[0]
	if tc.Name != "get_weather" {
		t.Errorf("Expected tool name 'get_weather', got '%s'", tc.Name)
	}
	if tc.ID != "call_xyz" {
		t.Errorf("Expected tool ID 'call_xyz', got '%s'", tc.ID)
	}

	var args map[string]string
	if err := json.Unmarshal(tc.Arguments, &args); err != nil {
		t.Fatalf("Failed to unmarshal arguments: %v", err)
	}
	if args["location"] != "Paris" {
		t.Errorf("Expected location 'Paris', got '%s'", args["location"])
	}
}
