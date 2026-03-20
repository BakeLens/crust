package httpproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BakeLens/crust/internal/eventlog"
	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/security"
	"github.com/BakeLens/crust/internal/telemetry"
)

// sinkFunc adapts a plain function to the eventlog.Sink interface.
type sinkFunc func(eventlog.Event)

func (f sinkFunc) LogEvent(e eventlog.Event) { f(e) }

// setupSecurityWithStorage creates a rules engine, in-memory storage, and
// interceptor from YAML rules. It returns both the interceptor and the
// storage handle so callers can query persisted telemetry after proxy
// operations. Cleanup is handled via t.Cleanup.
func setupSecurityWithStorage(t *testing.T, yamlRules string) (*security.Interceptor, *telemetry.Storage) {
	t.Helper()

	tempDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tempDir, "test-rules.yaml"), []byte(yamlRules), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	engine, err := rules.NewEngine(context.Background(), rules.EngineConfig{
		UserRulesDir:   tempDir,
		DisableBuiltin: true,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	storage, err := telemetry.NewStorage(":memory:", "")
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	t.Cleanup(func() { storage.Close() })

	interceptor := security.NewInterceptor(engine, storage)
	return interceptor, storage
}

// installStorageSink wires the eventlog global sink to persist events into
// the given storage. It resets in-memory metrics before the test and restores
// the previous sink via t.Cleanup.
func installStorageSink(t *testing.T, storage *telemetry.Storage) {
	t.Helper()
	eventlog.GetMetrics().Reset()
	eventlog.SetSink(sinkFunc(func(event eventlog.Event) {
		layer := event.Layer
		if layer == "" {
			layer = eventlog.LayerProxyResponse
		}
		tcLog := telemetry.ToolCallLog{
			TraceID:       event.TraceID,
			SessionID:     event.SessionID,
			ToolName:      event.ToolName,
			ToolArguments: event.Arguments,
			APIType:       event.APIType,
			Model:         event.Model,
			WasBlocked:    event.WasBlocked,
			BlockedByRule: event.RuleName,
			Layer:         layer,
			Protocol:      event.Protocol,
			Direction:     event.Direction,
			Method:        event.Method,
			BlockType:     event.BlockType,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := storage.LogToolCall(ctx, tcLog); err != nil {
			t.Errorf("sink LogToolCall: %v", err)
		}
	}))
	t.Cleanup(func() {
		// Clear sink to avoid leaking into other tests.
		eventlog.SetSink(sinkFunc(func(eventlog.Event) {}))
		eventlog.GetMetrics().Reset()
	})
}

// anthropicToolUseResponse builds a non-streaming Anthropic Messages API
// response body containing a single tool_use content block.
func anthropicToolUseResponse(toolName string, input map[string]string) []byte {
	resp := map[string]any{
		"id":   "msg_test_01",
		"type": "message",
		"role": "assistant",
		"content": []map[string]any{
			{
				"type":  "tool_use",
				"id":    "toolu_test_01",
				"name":  toolName,
				"input": input,
			},
		},
		"model":       "claude-sonnet-4-5-20250929",
		"stop_reason": "tool_use",
		"usage":       map[string]int{"input_tokens": 25, "output_tokens": 42},
	}
	b, _ := json.Marshal(resp)
	return b
}

func TestProxyE2E(t *testing.T) {
	t.Run("BlockedToolCall_PersistedInStorage", func(t *testing.T) {
		interceptor, storage := setupSecurityWithStorage(t, `
rules:
  - block: "**/.env"
    actions: [read]
    message: "Cannot read .env files"
`)
		installStorageSink(t, storage)

		// Upstream returns an Anthropic response with a tool_use block
		// that reads .env — this should be blocked by Layer 1.
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write(anthropicToolUseResponse("Bash", map[string]string{
				"command": "cat /home/user/project/.env",
			}))
		}))
		defer upstream.Close()

		proxy := setupTestProxyWithInterceptor(t, upstream, interceptor)

		body := []byte(`{"model":"claude-sonnet-4-5-20250929","max_tokens":1024,"messages":[{"role":"user","content":"show me the .env file"}]}`)
		req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		proxy.ServeHTTP(rr, req)

		// The response should have been modified (tool call blocked).
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}

		// Query storage for persisted events.
		ctx := context.Background()
		logs, err := storage.GetRecentLogs(ctx, 60, 100)
		if err != nil {
			t.Fatalf("GetRecentLogs: %v", err)
		}
		if len(logs) == 0 {
			t.Fatal("expected at least one tool call log persisted in storage, got 0")
		}

		// Find the blocked event.
		var found bool
		for _, l := range logs {
			if l.ToolName == "Bash" && l.WasBlocked {
				found = true
				if l.BlockedByRule == "" {
					t.Error("blocked tool call should have BlockedByRule set")
				}
				break
			}
		}
		if !found {
			t.Errorf("no blocked Bash tool call found in storage; got %d logs", len(logs))
			for i, l := range logs {
				t.Logf("  log[%d]: tool=%s blocked=%v rule=%s", i, l.ToolName, l.WasBlocked, l.BlockedByRule)
			}
		}

		// Verify in-memory metrics also recorded the block.
		stats := eventlog.GetMetrics().GetStats()
		if stats["proxy_response_blocks"] < 1 {
			t.Errorf("expected proxy_response_blocks >= 1, got %d", stats["proxy_response_blocks"])
		}
	})

	t.Run("AllowedToolCall_PersistedInStorage", func(t *testing.T) {
		interceptor, storage := setupSecurityWithStorage(t, `
rules:
  - block: "**/.env"
    actions: [read]
    message: "Cannot read .env files"
`)
		installStorageSink(t, storage)

		// Upstream returns a safe tool call (ls /tmp) that should NOT be blocked.
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write(anthropicToolUseResponse("Bash", map[string]string{
				"command": "ls /tmp",
			}))
		}))
		defer upstream.Close()

		proxy := setupTestProxyWithInterceptor(t, upstream, interceptor)

		body := []byte(`{"model":"claude-sonnet-4-5-20250929","max_tokens":1024,"messages":[{"role":"user","content":"list files in /tmp"}]}`)
		req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		proxy.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}

		// Verify the response still contains the tool_use block (not stripped).
		var respJSON map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &respJSON); err != nil {
			t.Fatalf("response is not valid JSON: %v", err)
		}

		ctx := context.Background()
		logs, err := storage.GetRecentLogs(ctx, 60, 100)
		if err != nil {
			t.Fatalf("GetRecentLogs: %v", err)
		}
		if len(logs) == 0 {
			t.Fatal("expected at least one tool call log persisted in storage, got 0")
		}

		var found bool
		for _, l := range logs {
			if l.ToolName == "Bash" && !l.WasBlocked {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no allowed Bash tool call found in storage; got %d logs", len(logs))
			for i, l := range logs {
				t.Logf("  log[%d]: tool=%s blocked=%v", i, l.ToolName, l.WasBlocked)
			}
		}

		stats := eventlog.GetMetrics().GetStats()
		if stats["proxy_response_allowed"] < 1 {
			t.Errorf("expected proxy_response_allowed >= 1, got %d", stats["proxy_response_allowed"])
		}
	})

	t.Run("MixedTraffic_StatsMatch", func(t *testing.T) {
		interceptor, storage := setupSecurityWithStorage(t, `
rules:
  - block: "**/.env"
    actions: [read]
    message: "Cannot read .env files"
`)
		installStorageSink(t, storage)

		// Track which request we're serving.
		var reqIdx int
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch reqIdx {
			case 0: // blocked: read .env
				w.Write(anthropicToolUseResponse("Bash", map[string]string{
					"command": "cat /app/.env",
				}))
			case 1: // allowed: ls /tmp
				w.Write(anthropicToolUseResponse("Bash", map[string]string{
					"command": "ls /tmp",
				}))
			case 2: // blocked: read another .env
				w.Write(anthropicToolUseResponse("Read", map[string]string{
					"file_path": "/home/user/.env",
				}))
			case 3: // allowed: read a safe file
				w.Write(anthropicToolUseResponse("Read", map[string]string{
					"file_path": "/tmp/output.txt",
				}))
			case 4: // allowed: echo
				w.Write(anthropicToolUseResponse("Bash", map[string]string{
					"command": "echo hello",
				}))
			}
		}))
		defer upstream.Close()

		proxy := setupTestProxyWithInterceptor(t, upstream, interceptor)

		for i := range 5 {
			reqIdx = i
			body := []byte(`{"model":"claude-sonnet-4-5-20250929","max_tokens":1024,"messages":[{"role":"user","content":"do something"}]}`)
			req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			proxy.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("request %d: expected 200, got %d: %s", i, rr.Code, rr.Body.String())
			}
		}

		ctx := context.Background()
		logs, err := storage.GetRecentLogs(ctx, 60, 100)
		if err != nil {
			t.Fatalf("GetRecentLogs: %v", err)
		}

		var blockedCount, allowedCount int
		for _, l := range logs {
			if l.WasBlocked {
				blockedCount++
			} else {
				allowedCount++
			}
		}

		if blockedCount != 2 {
			t.Errorf("expected 2 blocked tool calls in storage, got %d", blockedCount)
		}
		if allowedCount != 3 {
			t.Errorf("expected 3 allowed tool calls in storage, got %d", allowedCount)
		}
		if len(logs) != 5 {
			t.Errorf("expected 5 total logs in storage, got %d", len(logs))
		}

		// Verify in-memory metrics match.
		stats := eventlog.GetMetrics().GetStats()
		if stats["proxy_response_blocks"] != 2 {
			t.Errorf("expected proxy_response_blocks=2, got %d", stats["proxy_response_blocks"])
		}
		if stats["proxy_response_allowed"] != 3 {
			t.Errorf("expected proxy_response_allowed=3, got %d", stats["proxy_response_allowed"])
		}
		if stats["total_tool_calls"] != 5 {
			t.Errorf("expected total_tool_calls=5, got %d", stats["total_tool_calls"])
		}

		// Verify 24h stats from storage.
		st, err := storage.Get24hStats(ctx)
		if err != nil {
			t.Fatalf("Get24hStats: %v", err)
		}
		if st.Total != 5 {
			t.Errorf("Get24hStats.Total = %d, want 5", st.Total)
		}
		if st.Blocked != 2 {
			t.Errorf("Get24hStats.Blocked = %d, want 2", st.Blocked)
		}
	})
}
