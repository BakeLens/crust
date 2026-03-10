package security

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/types"
)

// createBenchInterceptor creates an interceptor for benchmarks.
// Uses builtin rules for realistic performance measurement.
func createBenchInterceptor(b *testing.B) (*Interceptor, func()) {
	b.Helper()

	tempDir := b.TempDir()

	engine, err := rules.NewEngine(context.Background(), rules.EngineConfig{
		UserRulesDir:   tempDir,
		DisableBuiltin: false, // use builtin rules for realistic benchmarks
	})
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}

	storage, err := telemetry.NewStorage(":memory:", "")
	if err != nil {
		b.Fatalf("Failed to create storage: %v", err)
	}

	interceptor := NewInterceptor(engine, storage)
	cleanup := func() {
		storage.Close()
	}

	return interceptor, cleanup
}

// =============================================================================
// Layer 0/1: Interceptor Benchmarks
// =============================================================================

// BenchmarkInterceptOpenAI benchmarks the full OpenAI intercept pipeline.
func BenchmarkInterceptOpenAI(b *testing.B) {
	interceptor, cleanup := createBenchInterceptor(b)
	defer cleanup()

	b.Run("allowed", func(b *testing.B) {
		b.ReportAllocs()
		resp := createOpenAIResponse([]openAIToolCall{
			{
				ID:   "call_1",
				Type: "function",
				Function: struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				}{
					Name:      "Bash",
					Arguments: `{"command": "echo hello"}`,
				},
			},
		}, "")
		b.ResetTimer()
		for b.Loop() {
			_, _ = interceptor.InterceptOpenAIResponse(resp, InterceptionContext{TraceID: "trace-1", SessionID: "sess-1", Model: "gpt-4", APIType: types.APITypeOpenAICompletion, BlockMode: types.BlockModeRemove})
		}
	})

	b.Run("blocked", func(b *testing.B) {
		b.ReportAllocs()
		resp := createOpenAIResponse([]openAIToolCall{
			{
				ID:   "call_1",
				Type: "function",
				Function: struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				}{
					Name:      "Read",
					Arguments: `{"path": "/home/user/.ssh/id_rsa"}`,
				},
			},
		}, "")
		b.ResetTimer()
		for b.Loop() {
			_, _ = interceptor.InterceptOpenAIResponse(resp, InterceptionContext{TraceID: "trace-1", SessionID: "sess-1", Model: "gpt-4", APIType: types.APITypeOpenAICompletion, BlockMode: types.BlockModeRemove})
		}
	})

	b.Run("mixed_5_tools", func(b *testing.B) {
		b.ReportAllocs()
		resp := createOpenAIResponse([]openAIToolCall{
			{ID: "c1", Type: "function", Function: struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			}{Name: "Bash", Arguments: `{"command": "ls -la"}`}},
			{ID: "c2", Type: "function", Function: struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			}{Name: "Read", Arguments: `{"path": "/home/user/.env"}`}},
			{ID: "c3", Type: "function", Function: struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			}{Name: "Write", Arguments: `{"path": "/tmp/out.txt", "content": "hello"}`}},
			{ID: "c4", Type: "function", Function: struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			}{Name: "Bash", Arguments: `{"command": "rm -rf /etc"}`}},
			{ID: "c5", Type: "function", Function: struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			}{Name: "Bash", Arguments: `{"command": "echo done"}`}},
		}, "")
		b.ResetTimer()
		for b.Loop() {
			_, _ = interceptor.InterceptOpenAIResponse(resp, InterceptionContext{TraceID: "trace-1", SessionID: "sess-1", Model: "gpt-4", APIType: types.APITypeOpenAICompletion, BlockMode: types.BlockModeRemove})
		}
	})
}

// BenchmarkInterceptAnthropic benchmarks the full Anthropic intercept pipeline.
func BenchmarkInterceptAnthropic(b *testing.B) {
	interceptor, cleanup := createBenchInterceptor(b)
	defer cleanup()

	b.Run("allowed", func(b *testing.B) {
		b.ReportAllocs()
		resp := createAnthropicResponse([]anthropicContentBlock{
			{
				Type:  "tool_use",
				ID:    "tu_1",
				Name:  "Bash",
				Input: json.RawMessage(`{"command": "echo hello"}`),
			},
		})
		b.ResetTimer()
		for b.Loop() {
			_, _ = interceptor.InterceptAnthropicResponse(resp, InterceptionContext{TraceID: "trace-1", SessionID: "sess-1", Model: "claude-3-opus", APIType: types.APITypeAnthropic, BlockMode: types.BlockModeRemove})
		}
	})

	b.Run("blocked", func(b *testing.B) {
		b.ReportAllocs()
		resp := createAnthropicResponse([]anthropicContentBlock{
			{
				Type:  "tool_use",
				ID:    "tu_1",
				Name:  "Read",
				Input: json.RawMessage(`{"path": "/home/user/.ssh/id_rsa"}`),
			},
		})
		b.ResetTimer()
		for b.Loop() {
			_, _ = interceptor.InterceptAnthropicResponse(resp, InterceptionContext{TraceID: "trace-1", SessionID: "sess-1", Model: "claude-3-opus", APIType: types.APITypeAnthropic, BlockMode: types.BlockModeRemove})
		}
	})

	b.Run("mixed_5_tools", func(b *testing.B) {
		b.ReportAllocs()
		resp := createAnthropicResponse([]anthropicContentBlock{
			{Type: "tool_use", ID: "tu_1", Name: "Bash", Input: json.RawMessage(`{"command": "ls -la"}`)},
			{Type: "tool_use", ID: "tu_2", Name: "Read", Input: json.RawMessage(`{"path": "/home/user/.env"}`)},
			{Type: "text", Text: "Let me help you"},
			{Type: "tool_use", ID: "tu_3", Name: "Write", Input: json.RawMessage(`{"path": "/tmp/out.txt", "content": "hello"}`)},
			{Type: "tool_use", ID: "tu_4", Name: "Bash", Input: json.RawMessage(`{"command": "rm -rf /etc"}`)},
		})
		b.ResetTimer()
		for b.Loop() {
			_, _ = interceptor.InterceptAnthropicResponse(resp, InterceptionContext{TraceID: "trace-1", SessionID: "sess-1", Model: "claude-3-opus", APIType: types.APITypeAnthropic, BlockMode: types.BlockModeRemove})
		}
	})
}

// BenchmarkInterceptOpenAIResponses benchmarks the OpenAI Responses API intercept pipeline.
func BenchmarkInterceptOpenAIResponses(b *testing.B) {
	interceptor, cleanup := createBenchInterceptor(b)
	defer cleanup()

	makeResp := func(items []openAIResponsesOutputItem) []byte {
		resp := openAIResponsesResponse{
			ID:     "resp_1",
			Object: "response",
			Model:  "gpt-4o",
			Output: items,
		}
		data, _ := json.Marshal(resp)
		return data
	}

	b.Run("allowed", func(b *testing.B) {
		b.ReportAllocs()
		resp := makeResp([]openAIResponsesOutputItem{
			{Type: "function_call", ID: "fc_1", CallID: "call_1", Name: "Bash", Arguments: `{"command": "echo hello"}`},
		})
		b.ResetTimer()
		for b.Loop() {
			_, _ = interceptor.InterceptOpenAIResponsesResponse(resp, InterceptionContext{TraceID: "trace-1", SessionID: "sess-1", Model: "gpt-4o", APIType: types.APITypeOpenAIResponses, BlockMode: types.BlockModeRemove})
		}
	})

	b.Run("blocked", func(b *testing.B) {
		b.ReportAllocs()
		resp := makeResp([]openAIResponsesOutputItem{
			{Type: "function_call", ID: "fc_1", CallID: "call_1", Name: "Read", Arguments: `{"path": "/home/user/.ssh/id_rsa"}`},
		})
		b.ResetTimer()
		for b.Loop() {
			_, _ = interceptor.InterceptOpenAIResponsesResponse(resp, InterceptionContext{TraceID: "trace-1", SessionID: "sess-1", Model: "gpt-4o", APIType: types.APITypeOpenAIResponses, BlockMode: types.BlockModeRemove})
		}
	})
}

// BenchmarkInterceptReplace benchmarks replace mode (echoes warning instead of removing).
func BenchmarkInterceptReplace(b *testing.B) {
	interceptor, cleanup := createBenchInterceptor(b)
	defer cleanup()

	b.Run("openai", func(b *testing.B) {
		b.ReportAllocs()
		resp := createOpenAIResponse([]openAIToolCall{
			{ID: "c1", Type: "function", Function: struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			}{Name: "Read", Arguments: `{"path": "/home/user/.env"}`}},
		}, "")
		b.ResetTimer()
		for b.Loop() {
			_, _ = interceptor.InterceptOpenAIResponse(resp, InterceptionContext{TraceID: "trace-1", SessionID: "sess-1", Model: "gpt-4", APIType: types.APITypeOpenAICompletion, BlockMode: types.BlockModeReplace})
		}
	})

	b.Run("anthropic", func(b *testing.B) {
		b.ReportAllocs()
		resp := createAnthropicResponse([]anthropicContentBlock{
			{Type: "tool_use", ID: "tu_1", Name: "Read", Input: json.RawMessage(`{"path": "/home/user/.env"}`)},
		})
		b.ResetTimer()
		for b.Loop() {
			_, _ = interceptor.InterceptAnthropicResponse(resp, InterceptionContext{TraceID: "trace-1", SessionID: "sess-1", Model: "claude-3-opus", APIType: types.APITypeAnthropic, BlockMode: types.BlockModeReplace})
		}
	})
}

// BenchmarkInterceptPassthrough benchmarks no-tool-call responses (fast path).
func BenchmarkInterceptPassthrough(b *testing.B) {
	interceptor, cleanup := createBenchInterceptor(b)
	defer cleanup()

	b.Run("openai_text_only", func(b *testing.B) {
		b.ReportAllocs()
		resp := createOpenAIResponse(nil, "Just a text response with no tool calls")
		b.ResetTimer()
		for b.Loop() {
			_, _ = interceptor.InterceptOpenAIResponse(resp, InterceptionContext{TraceID: "trace-1", SessionID: "sess-1", Model: "gpt-4", APIType: types.APITypeOpenAICompletion, BlockMode: types.BlockModeRemove})
		}
	})

	b.Run("anthropic_text_only", func(b *testing.B) {
		b.ReportAllocs()
		resp := createAnthropicResponse([]anthropicContentBlock{
			{Type: "text", Text: "Just a text response with no tool calls"},
		})
		b.ResetTimer()
		for b.Loop() {
			_, _ = interceptor.InterceptAnthropicResponse(resp, InterceptionContext{TraceID: "trace-1", SessionID: "sess-1", Model: "claude-3-opus", APIType: types.APITypeAnthropic, BlockMode: types.BlockModeRemove})
		}
	})
}

// BenchmarkNewInterceptor benchmarks the cost of creating an interceptor with the rules engine.
func BenchmarkNewInterceptor(b *testing.B) {
	b.ReportAllocs()
	tempDir := b.TempDir()
	rulePath := filepath.Join(tempDir, "test.yaml")
	_ = os.WriteFile(rulePath, []byte("rules:\n  - block: \"**/.env\"\n"), 0644)

	for b.Loop() {
		engine, _ := rules.NewEngine(context.Background(), rules.EngineConfig{
			UserRulesDir:   tempDir,
			DisableBuiltin: false,
		})
		_ = NewInterceptor(engine, nil)
	}
}
