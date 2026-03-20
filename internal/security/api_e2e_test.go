//go:build unix

package security

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BakeLens/crust/internal/eventlog"
	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/selfprotect"
	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/types"
)

// setupAPIE2E creates a full API server on a Unix socket and returns an HTTP
// client wired to that socket plus a seeded interceptor for further use.
func setupAPIE2E(t *testing.T) (client *http.Client, interceptor *Interceptor, storage *telemetry.Storage, rulesDir string) {
	t.Helper()

	// 1. Rules engine with builtin rules + selfprotect pre-checker.
	rulesDir = setupTestRulesDir(t, "")
	engine, err := rules.NewEngine(context.Background(), rules.EngineConfig{
		UserRulesDir:   rulesDir,
		DisableBuiltin: false,
		PreChecker:     selfprotect.Check,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// 2. In-memory telemetry storage.
	storage, err = telemetry.NewStorage(":memory:", "")
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	t.Cleanup(func() { storage.Close() })

	// 3. Interceptor + event sink so interceptions persist to storage.
	interceptor = NewInterceptor(engine, storage)
	eventlog.SetSink(storageSink{storage: storage})

	// 4. Manager (lightweight, for test).
	manager := NewManagerForTest(interceptor)

	// 5. API server.
	apiSrv := NewAPIServer(storage, interceptor, engine, manager)

	// 6. Unix socket listener.
	dir := shortTempDir(t)
	sockPath := filepath.Join(dir, "api-e2e.sock")
	ln, err := apiListener(sockPath)
	if err != nil {
		t.Fatalf("apiListener: %v", err)
	}
	t.Cleanup(func() {
		cleanupSocket(sockPath)
	})

	srv := &http.Server{Handler: apiSrv.Handler()}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	// Brief wait for the server goroutine to start accepting.
	time.Sleep(50 * time.Millisecond)

	// 7. HTTP client wired through the Unix socket.
	client = &http.Client{Transport: APITransport(sockPath)}

	return client, interceptor, storage, rulesDir
}

const apiBase = "http://crust-api"

// getJSON is a test helper that GETs a URL and returns the status code + body bytes.
func getJSON(t *testing.T, client *http.Client, path string) (int, []byte) {
	t.Helper()
	resp, err := client.Get(apiBase + path)
	if err != nil || resp == nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body %s: %v", path, err)
	}
	return resp.StatusCode, body
}

// postBody is a test helper that POSTs a body to a URL and returns status + body.
func postBody(t *testing.T, client *http.Client, path, contentType, body string) (int, []byte) {
	t.Helper()
	resp, err := client.Post(apiBase+path, contentType, strings.NewReader(body))
	if err != nil || resp == nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body %s: %v", path, err)
	}
	return resp.StatusCode, data
}

// deleteReq is a test helper that sends a DELETE request and returns status + body.
func deleteReq(t *testing.T, client *http.Client, path string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, apiBase+path, nil)
	if err != nil {
		t.Fatalf("new DELETE request %s: %v", path, err)
	}
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		t.Fatalf("DELETE %s: %v", path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body %s: %v", path, err)
	}
	return resp.StatusCode, data
}

// mustUnmarshalMap unmarshals JSON bytes into a map.
func mustUnmarshalMap(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal map: %v\nbody: %s", err, data)
	}
	return m
}

func TestAPIE2E(t *testing.T) {
	client, interceptor, storage, _ := setupAPIE2E(t)

	// Reset metrics to start clean.
	eventlog.GetMetrics().Reset()

	t.Run("Health", func(t *testing.T) {
		status, body := getJSON(t, client, "/health")
		if status != 200 {
			t.Fatalf("status = %d, want 200", status)
		}
		if string(body) != "OK" {
			t.Errorf("body = %q, want %q", body, "OK")
		}
	})

	t.Run("SecurityStatus", func(t *testing.T) {
		status, body := getJSON(t, client, "/api/security/status")
		if status != 200 {
			t.Fatalf("status = %d, want 200", status)
		}
		m := mustUnmarshalMap(t, body)
		if enabled, ok := m["enabled"].(bool); !ok || !enabled {
			t.Errorf("enabled = %v, want true", m["enabled"])
		}
		if rc, ok := m["rules_count"].(float64); !ok || rc <= 0 {
			t.Errorf("rules_count = %v, want > 0", m["rules_count"])
		}
	})

	t.Run("SecurityStats", func(t *testing.T) {
		status, body := getJSON(t, client, "/api/security/stats")
		if status != 200 {
			t.Fatalf("status = %d, want 200", status)
		}
		m := mustUnmarshalMap(t, body)
		// After Reset(), all counters should be 0.
		for _, key := range []string{"total_tool_calls", "blocked_tool_calls", "allowed_tool_calls"} {
			if v, ok := m[key].(float64); !ok || v != 0 {
				t.Errorf("%s = %v, want 0", key, m[key])
			}
		}
	})

	t.Run("SecurityLogs_Empty", func(t *testing.T) {
		// With fresh storage (no seeded data in this test), logs may be empty.
		status, body := getJSON(t, client, "/api/security/logs")
		if status != 200 {
			t.Fatalf("status = %d, want 200", status)
		}
		var logs []any
		if err := json.Unmarshal(body, &logs); err != nil {
			t.Fatalf("unmarshal logs: %v\nbody: %s", err, body)
		}
		// Logs array exists (may be empty or contain prior data).
	})

	t.Run("TelemetrySessions_Empty", func(t *testing.T) {
		status, body := getJSON(t, client, "/api/telemetry/sessions")
		if status != 200 {
			t.Fatalf("status = %d, want 200", status)
		}
		var arr []any
		if err := json.Unmarshal(body, &arr); err != nil {
			t.Fatalf("unmarshal sessions: %v\nbody: %s", err, body)
		}
	})

	t.Run("TelemetryTraces_Empty", func(t *testing.T) {
		status, body := getJSON(t, client, "/api/telemetry/traces")
		if status != 200 {
			t.Fatalf("status = %d, want 200", status)
		}
		var arr []any
		if err := json.Unmarshal(body, &arr); err != nil {
			t.Fatalf("unmarshal traces: %v\nbody: %s", err, body)
		}
	})

	t.Run("TelemetryStats", func(t *testing.T) {
		status, body := getJSON(t, client, "/api/telemetry/stats")
		if status != 200 {
			t.Fatalf("status = %d, want 200", status)
		}
		mustUnmarshalMap(t, body)
	})

	t.Run("TelemetryStatsTrend", func(t *testing.T) {
		status, body := getJSON(t, client, "/api/telemetry/stats/trend?range=7d")
		if status != 200 {
			t.Fatalf("status = %d, want 200", status)
		}
		var arr []any
		if err := json.Unmarshal(body, &arr); err != nil {
			t.Fatalf("unmarshal trend: %v\nbody: %s", err, body)
		}
	})

	t.Run("TelemetryStatsDistribution", func(t *testing.T) {
		status, body := getJSON(t, client, "/api/telemetry/stats/distribution?range=30d")
		if status != 200 {
			t.Fatalf("status = %d, want 200", status)
		}
		mustUnmarshalMap(t, body)
	})

	t.Run("TelemetryStatsCoverage", func(t *testing.T) {
		status, body := getJSON(t, client, "/api/telemetry/stats/coverage?range=30d")
		if status != 200 {
			t.Fatalf("status = %d, want 200", status)
		}
		var arr []any
		if err := json.Unmarshal(body, &arr); err != nil {
			t.Fatalf("unmarshal coverage: %v\nbody: %s", err, body)
		}
	})

	t.Run("RulesListAll", func(t *testing.T) {
		status, body := getJSON(t, client, "/api/crust/rules")
		if status != 200 {
			t.Fatalf("status = %d, want 200", status)
		}
		m := mustUnmarshalMap(t, body)
		if total, ok := m["total"].(float64); !ok || total <= 0 {
			t.Errorf("total = %v, want > 0", m["total"])
		}
	})

	t.Run("RulesListBuiltin", func(t *testing.T) {
		status, body := getJSON(t, client, "/api/crust/rules/builtin")
		if status != 200 {
			t.Fatalf("status = %d, want 200", status)
		}
		m := mustUnmarshalMap(t, body)
		if total, ok := m["total"].(float64); !ok || total <= 0 {
			t.Errorf("total = %v, want > 0", m["total"])
		}
	})

	t.Run("RulesListUser", func(t *testing.T) {
		status, body := getJSON(t, client, "/api/crust/rules/user")
		if status != 200 {
			t.Fatalf("status = %d, want 200", status)
		}
		m := mustUnmarshalMap(t, body)
		// User rules may be empty initially; just verify the response shape.
		if _, ok := m["total"]; !ok {
			t.Error("response missing 'total' field")
		}
	})

	t.Run("RulesValidateValid", func(t *testing.T) {
		validYAML := `rules:
  - name: test-rule
    block: "/tmp/blocked/**"
    actions: [read]
    message: "blocked"
`
		status, body := postBody(t, client, "/api/crust/rules/validate", "application/yaml", validYAML)
		if status != 200 {
			t.Fatalf("status = %d, want 200", status)
		}
		m := mustUnmarshalMap(t, body)
		if valid, ok := m["valid"].(bool); !ok || !valid {
			t.Errorf("valid = %v, want true", m["valid"])
		}
	})

	t.Run("RulesValidateInvalid", func(t *testing.T) {
		invalidYAML := `this is not valid rules yaml: [[[`
		status, body := postBody(t, client, "/api/crust/rules/validate", "application/yaml", invalidYAML)
		if status != 200 {
			t.Fatalf("status = %d, want 200", status)
		}
		m := mustUnmarshalMap(t, body)
		if valid, ok := m["valid"].(bool); ok && valid {
			t.Errorf("valid = %v, want false", m["valid"])
		}
	})

	t.Run("RulesAddFile", func(t *testing.T) {
		ruleYAML := `rules:
  - name: e2e-added-rule
    block: "/tmp/e2e-test/**"
    actions: [read]
    message: "e2e test rule"
`
		status, body := postBody(t, client,
			"/api/crust/rules/files?filename=test-added.yaml",
			"application/yaml", ruleYAML)
		if status != 200 {
			t.Fatalf("status = %d, want 200\nbody: %s", status, body)
		}
		m := mustUnmarshalMap(t, body)
		if s, ok := m["status"].(string); !ok || s != "added" {
			t.Errorf("status = %v, want %q", m["status"], "added")
		}

		// Verify the file was actually written.
		engine := interceptor.GetEngine().(*rules.Engine)
		userDir := engine.GetLoader().GetUserDir()
		if _, err := os.Stat(filepath.Join(userDir, "test-added.yaml")); err != nil {
			t.Errorf("rule file not found on disk: %v", err)
		}
	})

	t.Run("RulesListFiles", func(t *testing.T) {
		status, body := getJSON(t, client, "/api/crust/rules/files")
		if status != 200 {
			t.Fatalf("status = %d, want 200", status)
		}
		m := mustUnmarshalMap(t, body)
		files, ok := m["files"]
		if !ok {
			t.Fatal("response missing 'files' field")
		}
		// After RulesAddFile, the files list should include the added file.
		filesArr, ok := files.([]any)
		if !ok {
			t.Fatalf("files is not an array: %T", files)
		}
		found := false
		for _, f := range filesArr {
			if fm, ok := f.(map[string]any); ok {
				if name, _ := fm["name"].(string); name == "test-added.yaml" {
					found = true
					break
				}
			}
			// Also handle case where files are plain strings.
			if name, ok := f.(string); ok && name == "test-added.yaml" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("test-added.yaml not found in files list: %s", body)
		}
	})

	t.Run("RulesReload", func(t *testing.T) {
		status, body := postBody(t, client, "/api/crust/rules/reload", "application/json", "")
		if status != 200 {
			t.Fatalf("status = %d, want 200", status)
		}
		m := mustUnmarshalMap(t, body)
		if s, ok := m["status"].(string); !ok || s != "reloaded" {
			t.Errorf("status = %v, want %q", m["status"], "reloaded")
		}
	})

	t.Run("RulesDeleteFile", func(t *testing.T) {
		status, body := deleteReq(t, client, "/api/crust/rules/user/test-added.yaml")
		if status != 200 {
			t.Fatalf("status = %d, want 200\nbody: %s", status, body)
		}
		m := mustUnmarshalMap(t, body)
		if s, ok := m["status"].(string); !ok || s != "deleted" {
			t.Errorf("status = %v, want %q", m["status"], "deleted")
		}
	})

	t.Run("Plugins", func(t *testing.T) {
		status, body := getJSON(t, client, "/api/security/plugins")
		if status != 200 {
			t.Fatalf("status = %d, want 200", status)
		}
		var arr []any
		if err := json.Unmarshal(body, &arr); err != nil {
			t.Fatalf("unmarshal plugins: %v\nbody: %s", err, body)
		}
		// Array returned (may be empty for test manager with nil registry).
	})

	t.Run("Agents", func(t *testing.T) {
		status, body := getJSON(t, client, "/api/security/agents")
		if status != 200 {
			t.Fatalf("status = %d, want 200", status)
		}
		var arr []any
		if err := json.Unmarshal(body, &arr); err != nil {
			t.Fatalf("unmarshal agents: %v\nbody: %s", err, body)
		}
		// Array returned (contents depend on local agent detection).
	})

	t.Run("Integration_BlockedCallAppearsInLogsAndStats", func(t *testing.T) {
		// a. Reset metrics to get a clean baseline.
		eventlog.GetMetrics().Reset()

		// b. Event sink is already wired via setupAPIE2E (storageSink{storage}).
		_ = storage // already connected

		// c. Intercept a blocked .env read.
		blockedResp := createAnthropicResponse([]anthropicContentBlock{
			{Type: "tool_use", ID: "integ1", Name: "Read", Input: json.RawMessage(`{"file_path":"/home/user/.env"}`)},
		})
		result, err := interceptor.InterceptToolCalls(blockedResp, InterceptionContext{
			TraceID:   types.TraceID(fmt.Sprintf("trace-integ-%d", time.Now().UnixNano())),
			SessionID: "session-integ",
			Model:     "claude-3-opus",
			APIType:   types.APITypeAnthropic,
			BlockMode: types.BlockModeRemove,
		})
		if err != nil {
			t.Fatalf("InterceptToolCalls: %v", err)
		}
		if len(result.BlockedToolCalls) != 1 {
			t.Fatalf("expected 1 blocked, got %d", len(result.BlockedToolCalls))
		}

		// Give the async sink a moment to persist.
		time.Sleep(50 * time.Millisecond)

		// d. Verify /api/security/stats shows blocked_tool_calls > 0.
		status, body := getJSON(t, client, "/api/security/stats")
		if status != 200 {
			t.Fatalf("stats status = %d", status)
		}
		statsMap := mustUnmarshalMap(t, body)
		if blocked, ok := statsMap["blocked_tool_calls"].(float64); !ok || blocked <= 0 {
			t.Errorf("blocked_tool_calls = %v, want > 0", statsMap["blocked_tool_calls"])
		}

		// e. Verify /api/security/logs contains the blocked tool call.
		status, body = getJSON(t, client, "/api/security/logs?minutes=5&limit=100")
		if status != 200 {
			t.Fatalf("logs status = %d", status)
		}
		var logs []map[string]any
		if err := json.Unmarshal(body, &logs); err != nil {
			t.Fatalf("unmarshal logs: %v\nbody: %s", err, body)
		}
		found := false
		for _, logEntry := range logs {
			if name, _ := logEntry["tool_name"].(string); name == "Read" {
				if blocked, _ := logEntry["was_blocked"].(bool); blocked {
					found = true
					break
				}
			}
		}
		if !found {
			t.Error("blocked Read event not found in security logs")
		}
	})
}
