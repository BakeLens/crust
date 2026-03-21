package proxyutil

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/security"
	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/types"
)

func TestInterceptResponse_NilInterceptor(t *testing.T) {
	body := []byte(`{"content":[{"type":"text","text":"ok"}]}`)
	result, blocked := InterceptResponse(body, "", nil, DefaultInterceptionContext(types.APITypeAnthropic, types.BlockModeRemove))
	if blocked != 0 {
		t.Errorf("expected 0 blocked with nil interceptor, got %d", blocked)
	}
	if string(result) != string(body) {
		t.Error("expected body unchanged with nil interceptor")
	}
}

func TestInterceptResponse_BlocksToolCall(t *testing.T) {
	interceptor := setupInterceptor(t, `
rules:
  - block: "**/.env"
    actions: [read]
    message: "Cannot read .env files"
`)
	// Anthropic response with a tool_use block reading .env
	resp := mustJSON(t, map[string]any{
		"id":   "msg_1",
		"type": "message",
		"role": "assistant",
		"content": []map[string]any{
			{"type": "text", "text": "Let me read that."},
			{"type": "tool_use", "id": "t1", "name": "Read", "input": map[string]string{"file_path": "/app/.env"}},
		},
	})

	result, blocked := InterceptResponse(resp, "", interceptor, DefaultInterceptionContext(types.APITypeAnthropic, types.BlockModeRemove))
	if blocked != 1 {
		t.Fatalf("expected 1 blocked, got %d", blocked)
	}
	if string(result) == string(resp) {
		t.Error("expected modified response")
	}
}

func TestInterceptResponse_AllowsSafeToolCall(t *testing.T) {
	interceptor := setupInterceptor(t, `
rules:
  - block: "**/.env"
    actions: [read]
`)
	resp := mustJSON(t, map[string]any{
		"id":   "msg_1",
		"type": "message",
		"role": "assistant",
		"content": []map[string]any{
			{"type": "tool_use", "id": "t1", "name": "Read", "input": map[string]string{"file_path": "/tmp/safe.txt"}},
		},
	})

	result, blocked := InterceptResponse(resp, "", interceptor, DefaultInterceptionContext(types.APITypeAnthropic, types.BlockModeRemove))
	if blocked != 0 {
		t.Errorf("expected 0 blocked, got %d", blocked)
	}
	if string(result) != string(resp) {
		t.Error("safe tool call should not modify response")
	}
}

func TestInterceptResponse_GzipRoundtrip(t *testing.T) {
	interceptor := setupInterceptor(t, `
rules:
  - block: "**/.env"
    actions: [read]
`)
	resp := mustJSON(t, map[string]any{
		"id":   "msg_1",
		"type": "message",
		"role": "assistant",
		"content": []map[string]any{
			{"type": "tool_use", "id": "t1", "name": "Read", "input": map[string]string{"file_path": "/app/.env"}},
		},
	})

	compressed, err := CompressGzip(resp)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}

	result, blocked := InterceptResponse(compressed, "gzip", interceptor, DefaultInterceptionContext(types.APITypeAnthropic, types.BlockModeRemove))
	if blocked != 1 {
		t.Fatalf("expected 1 blocked in gzip response, got %d", blocked)
	}

	// Result should be valid gzip
	decompressed, err := DecompressGzip(result)
	if err != nil {
		t.Fatalf("result should be valid gzip: %v", err)
	}
	if len(decompressed) == 0 {
		t.Error("decompressed result should not be empty")
	}
}

func TestInterceptResponse_InvalidGzip(t *testing.T) {
	body := []byte("not gzip data at all")
	result, blocked := InterceptResponse(body, "gzip", nil, DefaultInterceptionContext(types.APITypeAnthropic, types.BlockModeRemove))
	if blocked != 0 {
		t.Errorf("expected 0 blocked, got %d", blocked)
	}
	if string(result) != string(body) {
		t.Error("invalid gzip should return original body")
	}
}

func TestDefaultInterceptionContext(t *testing.T) {
	ctx := DefaultInterceptionContext(types.APITypeAnthropic, types.BlockModeReplace)
	if ctx.APIType != types.APITypeAnthropic {
		t.Errorf("APIType = %v, want Anthropic", ctx.APIType)
	}
	if ctx.BlockMode != types.BlockModeReplace {
		t.Errorf("BlockMode = %v, want Replace", ctx.BlockMode)
	}
}

// ── helpers ──

func setupInterceptor(t *testing.T, yamlRules string) *security.Interceptor {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(yamlRules), 0644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	engine, err := rules.NewEngine(context.Background(), rules.EngineConfig{
		UserRulesDir:   dir,
		DisableBuiltin: true,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(engine.Close)
	return security.NewInterceptor(engine, telemetry.NopRecorder{})
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}
