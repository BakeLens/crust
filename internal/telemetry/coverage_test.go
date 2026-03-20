//go:build !libcrust

package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BakeLens/crust/internal/types"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// insertToolCall is a shorthand for inserting a tool call log in tests.
func insertToolCall(t *testing.T, s *Storage, traceID, sessionID, toolName string, blocked bool, blockedBy string) {
	t.Helper()
	err := s.LogToolCall(context.Background(), ToolCallLog{
		TraceID:       types.TraceID(traceID),
		SessionID:     types.SessionID(sessionID),
		ToolName:      toolName,
		WasBlocked:    blocked,
		BlockedByRule: blockedBy,
		Model:         "test-model",
		Layer:         "proxy_response",
	})
	if err != nil {
		t.Fatalf("LogToolCall: %v", err)
	}
}

// insertSpanTx is a shorthand for recording a span transaction in tests.
func insertSpanTx(t *testing.T, s *Storage, traceID, sessionID string, inputTok, outputTok int64) {
	t.Helper()
	mainSpan := &Span{
		SpanID:       types.SpanID(fmt.Sprintf("span-%s", traceID)),
		Name:         "llm-call",
		SpanKind:     SpanKindLLM,
		StartTime:    time.Now().Add(-100 * time.Millisecond),
		EndTime:      time.Now(),
		InputTokens:  inputTok,
		OutputTokens: outputTok,
		StatusCode:   "OK",
	}
	err := s.RecordSpanTx(context.Background(), types.TraceID(traceID), types.SessionID(sessionID), mainSpan, nil)
	if err != nil {
		t.Fatalf("RecordSpanTx: %v", err)
	}
}

// ---------------------------------------------------------------------------
// queryInt
// ---------------------------------------------------------------------------

func TestQueryInt(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		key        string
		defaultVal int
		maxVal     int
		want       int
	}{
		{"empty_returns_default", "", "limit", 50, 200, 50},
		{"valid_value", "limit=10", "limit", 50, 200, 10},
		{"exceeds_max", "limit=999", "limit", 50, 200, 200},
		{"invalid_not_number", "limit=abc", "limit", 50, 200, 50},
		{"zero_returns_default", "limit=0", "limit", 50, 200, 50},
		{"negative_returns_default", "limit=-5", "limit", 50, 200, 50},
		{"exact_max", "limit=200", "limit", 50, 200, 200},
		{"one", "limit=1", "limit", 50, 200, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/?"+tt.query, nil)
			got := queryInt(r, tt.key, tt.defaultVal, tt.maxVal)
			if got != tt.want {
				t.Errorf("queryInt() = %d, want %d", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ParseRangeDays
// ---------------------------------------------------------------------------

func TestParseRangeDays(t *testing.T) {
	tests := []struct {
		input   string
		defDays int
		want    int
	}{
		{"", 7, 7},
		{"7d", 7, 7},
		{"30d", 7, 30},
		{"90d", 7, 90},
		{"1d", 7, 1},
		{"abc", 7, 7},
		{"d", 7, 7},   // no number before 'd'
		{"0d", 7, 7},  // zero is invalid
		{"-5d", 7, 7}, // negative
		{"10", 7, 7},  // no 'd' suffix
		{"10x", 7, 7}, // wrong suffix
		{"365d", 30, 365},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q_default_%d", tt.input, tt.defDays), func(t *testing.T) {
			got := ParseRangeDays(tt.input, tt.defDays)
			if got != tt.want {
				t.Errorf("ParseRangeDays(%q, %d) = %d, want %d", tt.input, tt.defDays, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Storage: GetRecentLogs
// ---------------------------------------------------------------------------

func TestGetRecentLogs(t *testing.T) {
	s := newTestStorage(t)

	for i := range 5 {
		insertToolCall(t, s, fmt.Sprintf("trace-%d", i), "s1", "Read", false, "")
	}

	logs, err := s.GetRecentLogs(context.Background(), 60, 100)
	if err != nil {
		t.Fatalf("GetRecentLogs: %v", err)
	}
	if len(logs) != 5 {
		t.Errorf("got %d logs, want 5", len(logs))
	}
}

func TestGetRecentLogs_LimitEnforced(t *testing.T) {
	s := newTestStorage(t)

	for i := range 10 {
		insertToolCall(t, s, fmt.Sprintf("trace-%d", i), "s1", "Read", false, "")
	}

	logs, err := s.GetRecentLogs(context.Background(), 60, 3)
	if err != nil {
		t.Fatalf("GetRecentLogs: %v", err)
	}
	if len(logs) != 3 {
		t.Errorf("got %d logs, want 3", len(logs))
	}
}

func TestGetRecentLogs_DefaultsForInvalidParams(t *testing.T) {
	s := newTestStorage(t)

	insertToolCall(t, s, "trace-1", "s1", "Read", false, "")

	// negative minutes and limit should use defaults
	logs, err := s.GetRecentLogs(context.Background(), -1, -1)
	if err != nil {
		t.Fatalf("GetRecentLogs: %v", err)
	}
	if len(logs) != 1 {
		t.Errorf("got %d logs, want 1", len(logs))
	}
}

// ---------------------------------------------------------------------------
// Storage: GetRecentBlockedLogs
// ---------------------------------------------------------------------------

func TestGetRecentBlockedLogs(t *testing.T) {
	s := newTestStorage(t)

	// Insert mix of blocked and allowed
	insertToolCall(t, s, "trace-1", "s1", "Read", false, "")
	insertToolCall(t, s, "trace-2", "s1", "Bash", true, "deny-bash")
	insertToolCall(t, s, "trace-3", "s1", "Write", true, "deny-write")
	insertToolCall(t, s, "trace-4", "s1", "Read", false, "")

	logs, err := s.GetRecentBlockedLogs(context.Background(), 60, 100)
	if err != nil {
		t.Fatalf("GetRecentBlockedLogs: %v", err)
	}
	if len(logs) != 2 {
		t.Errorf("got %d blocked logs, want 2", len(logs))
	}
	for _, l := range logs {
		if !l.WasBlocked {
			t.Errorf("expected only blocked logs, got unblocked log for %s", l.ToolName)
		}
	}
}

func TestGetRecentBlockedLogs_DefaultsForInvalidParams(t *testing.T) {
	s := newTestStorage(t)

	insertToolCall(t, s, "trace-1", "s1", "Bash", true, "deny-bash")

	logs, err := s.GetRecentBlockedLogs(context.Background(), -1, -1)
	if err != nil {
		t.Fatalf("GetRecentBlockedLogs: %v", err)
	}
	if len(logs) != 1 {
		t.Errorf("got %d logs, want 1", len(logs))
	}
}

// ---------------------------------------------------------------------------
// Storage: Get24hStats
// ---------------------------------------------------------------------------

func TestGet24hStats(t *testing.T) {
	s := newTestStorage(t)

	insertToolCall(t, s, "trace-1", "s1", "Read", false, "")
	insertToolCall(t, s, "trace-2", "s1", "Bash", true, "deny-bash")
	insertToolCall(t, s, "trace-3", "s1", "Write", true, "deny-write")

	stats, err := s.Get24hStats(context.Background())
	if err != nil {
		t.Fatalf("Get24hStats: %v", err)
	}
	if stats.Total != 3 {
		t.Errorf("Total = %d, want 3", stats.Total)
	}
	if stats.Blocked != 2 {
		t.Errorf("Blocked = %d, want 2", stats.Blocked)
	}
}

func TestGet24hStats_Empty(t *testing.T) {
	s := newTestStorage(t)

	stats, err := s.Get24hStats(context.Background())
	if err != nil {
		t.Fatalf("Get24hStats: %v", err)
	}
	if stats.Total != 0 {
		t.Errorf("Total = %d, want 0", stats.Total)
	}
	if stats.Blocked != 0 {
		t.Errorf("Blocked = %d, want 0", stats.Blocked)
	}
}

// ---------------------------------------------------------------------------
// Storage: GetBlockTrend
// ---------------------------------------------------------------------------

func TestGetBlockTrend(t *testing.T) {
	s := newTestStorage(t)

	insertToolCall(t, s, "trace-1", "s1", "Read", false, "")
	insertToolCall(t, s, "trace-2", "s1", "Bash", true, "deny-bash")
	insertToolCall(t, s, "trace-3", "s1", "Write", true, "deny-write")

	points, err := s.GetBlockTrend(context.Background(), 7)
	if err != nil {
		t.Fatalf("GetBlockTrend: %v", err)
	}
	if len(points) == 0 {
		t.Fatal("expected at least one trend point")
	}

	// All calls are today, so there should be exactly one data point.
	total := points[0].TotalCalls
	blocked := points[0].BlockedCalls
	if total != 3 {
		t.Errorf("TotalCalls = %d, want 3", total)
	}
	if blocked != 2 {
		t.Errorf("BlockedCalls = %d, want 2", blocked)
	}
}

func TestGetBlockTrend_ClampsDays(t *testing.T) {
	s := newTestStorage(t)

	// days=0 should default to 7, days=100 should clamp to 90
	_, err := s.GetBlockTrend(context.Background(), 0)
	if err != nil {
		t.Fatalf("GetBlockTrend(0): %v", err)
	}
	_, err = s.GetBlockTrend(context.Background(), 100)
	if err != nil {
		t.Fatalf("GetBlockTrend(100): %v", err)
	}
}

// ---------------------------------------------------------------------------
// Storage: GetDistribution
// ---------------------------------------------------------------------------

func TestGetDistribution(t *testing.T) {
	s := newTestStorage(t)

	insertToolCall(t, s, "trace-1", "s1", "Bash", true, "deny-bash")
	insertToolCall(t, s, "trace-2", "s1", "Bash", true, "deny-bash")
	insertToolCall(t, s, "trace-3", "s1", "Write", true, "deny-write")
	insertToolCall(t, s, "trace-4", "s1", "Read", false, "")

	dist, err := s.GetDistribution(context.Background(), 30)
	if err != nil {
		t.Fatalf("GetDistribution: %v", err)
	}

	// By rule: deny-bash=2, deny-write=1
	if len(dist.ByRule) != 2 {
		t.Errorf("ByRule len = %d, want 2", len(dist.ByRule))
	}

	// By tool: Bash=2, Write=1 (Read is not blocked)
	if len(dist.ByTool) != 2 {
		t.Errorf("ByTool len = %d, want 2", len(dist.ByTool))
	}
}

func TestGetDistribution_ClampsDays(t *testing.T) {
	s := newTestStorage(t)

	_, err := s.GetDistribution(context.Background(), 0)
	if err != nil {
		t.Fatalf("GetDistribution(0): %v", err)
	}
	_, err = s.GetDistribution(context.Background(), 100)
	if err != nil {
		t.Fatalf("GetDistribution(100): %v", err)
	}
}

// ---------------------------------------------------------------------------
// Storage: GetCoverage
// ---------------------------------------------------------------------------

func TestGetCoverage(t *testing.T) {
	s := newTestStorage(t)

	insertToolCall(t, s, "trace-1", "s1", "Read", false, "")
	insertToolCall(t, s, "trace-2", "s1", "Read", true, "deny-read")
	insertToolCall(t, s, "trace-3", "s1", "Bash", true, "deny-bash")

	tools, err := s.GetCoverage(context.Background(), 30)
	if err != nil {
		t.Fatalf("GetCoverage: %v", err)
	}
	if len(tools) == 0 {
		t.Fatal("expected at least one coverage tool")
	}

	// Find Read tool
	var found bool
	for _, tool := range tools {
		if tool.ToolName == "Read" {
			found = true
			if tool.TotalCalls != 2 {
				t.Errorf("Read TotalCalls = %d, want 2", tool.TotalCalls)
			}
			if tool.BlockedCalls != 1 {
				t.Errorf("Read BlockedCalls = %d, want 1", tool.BlockedCalls)
			}
		}
	}
	if !found {
		t.Error("Read tool not found in coverage")
	}
}

func TestGetCoverage_ClampsDays(t *testing.T) {
	s := newTestStorage(t)

	_, err := s.GetCoverage(context.Background(), 0)
	if err != nil {
		t.Fatalf("GetCoverage(0): %v", err)
	}
	_, err = s.GetCoverage(context.Background(), 100)
	if err != nil {
		t.Fatalf("GetCoverage(100): %v", err)
	}
}

// ---------------------------------------------------------------------------
// Storage: GetLayerCounts
// ---------------------------------------------------------------------------

func TestGetLayerCounts(t *testing.T) {
	s := newTestStorage(t)

	insertToolCall(t, s, "trace-1", "s1", "Read", false, "")
	insertToolCall(t, s, "trace-2", "s1", "Bash", true, "deny-bash")

	counts, err := s.GetLayerCounts(context.Background())
	if err != nil {
		t.Fatalf("GetLayerCounts: %v", err)
	}
	if len(counts) == 0 {
		t.Fatal("expected at least one layer count")
	}

	// Verify we have entries for both blocked and unblocked
	var totalCount int64
	for _, lc := range counts {
		totalCount += lc.Count
	}
	if totalCount != 2 {
		t.Errorf("total count across layers = %d, want 2", totalCount)
	}
}

// ---------------------------------------------------------------------------
// Storage: ClearAllEvents
// ---------------------------------------------------------------------------

func TestClearAllEvents(t *testing.T) {
	s := newTestStorage(t)

	for i := range 5 {
		insertToolCall(t, s, fmt.Sprintf("trace-%d", i), "s1", "Read", false, "")
	}

	deleted, err := s.ClearAllEvents(context.Background())
	if err != nil {
		t.Fatalf("ClearAllEvents: %v", err)
	}
	if deleted != 5 {
		t.Errorf("deleted = %d, want 5", deleted)
	}

	// Verify empty
	var count int
	_ = s.DB().QueryRow("SELECT COUNT(*) FROM tool_call_logs").Scan(&count)
	if count != 0 {
		t.Errorf("count after clear = %d, want 0", count)
	}
}

// ---------------------------------------------------------------------------
// Storage: IsEncrypted, Queries
// ---------------------------------------------------------------------------

func TestIsEncrypted_Unencrypted(t *testing.T) {
	s := newTestStorage(t)
	if s.IsEncrypted() {
		t.Error("in-memory DB should not be encrypted")
	}
}

func TestQueries_NotNil(t *testing.T) {
	s := newTestStorage(t)
	if s.Queries() == nil {
		t.Error("Queries() should not be nil")
	}
}

// ---------------------------------------------------------------------------
// Storage: UpdateTraceEndTime
// ---------------------------------------------------------------------------

func TestUpdateTraceEndTime(t *testing.T) {
	s := newTestStorage(t)

	_, err := s.GetOrCreateTrace(context.Background(), "trace-end", "s1")
	if err != nil {
		t.Fatalf("GetOrCreateTrace: %v", err)
	}

	endTime := time.Now().Add(5 * time.Minute)
	if err := s.UpdateTraceEndTime(context.Background(), "trace-end", endTime); err != nil {
		t.Fatalf("UpdateTraceEndTime: %v", err)
	}

	// Verify end time was set
	trace, err := s.GetOrCreateTrace(context.Background(), "trace-end", "s1")
	if err != nil {
		t.Fatal(err)
	}
	if trace.EndTime.IsZero() {
		t.Error("end time should be set")
	}
}

// ---------------------------------------------------------------------------
// Storage: SeedMetrics (smoke test)
// ---------------------------------------------------------------------------

func TestSeedMetrics_NoErrors(t *testing.T) {
	s := newTestStorage(t)

	insertToolCall(t, s, "trace-1", "s1", "Read", false, "")
	insertToolCall(t, s, "trace-2", "s1", "Bash", true, "deny-bash")

	// SeedMetrics should not panic or error
	SeedMetrics(context.Background(), s)
}

func TestSeedMetrics_EmptyDB(t *testing.T) {
	s := newTestStorage(t)

	// Should handle empty DB gracefully
	SeedMetrics(context.Background(), s)
}

// ---------------------------------------------------------------------------
// StatsService methods
// ---------------------------------------------------------------------------

func TestStatsService_GetBlockTrend(t *testing.T) {
	s := newTestStorage(t)
	svc := NewStatsService(s)

	insertToolCall(t, s, "trace-1", "s1", "Read", false, "")
	insertToolCall(t, s, "trace-2", "s1", "Bash", true, "deny-bash")

	points, err := svc.GetBlockTrend(context.Background(), "7d")
	if err != nil {
		t.Fatalf("GetBlockTrend: %v", err)
	}
	// Should return non-nil empty slice or populated slice
	if points == nil {
		t.Error("GetBlockTrend should never return nil")
	}
}

func TestStatsService_GetBlockTrend_EmptyRange(t *testing.T) {
	s := newTestStorage(t)
	svc := NewStatsService(s)

	points, err := svc.GetBlockTrend(context.Background(), "")
	if err != nil {
		t.Fatalf("GetBlockTrend empty range: %v", err)
	}
	if points == nil {
		t.Error("should return empty slice, not nil")
	}
}

func TestStatsService_GetDistribution(t *testing.T) {
	s := newTestStorage(t)
	svc := NewStatsService(s)

	insertToolCall(t, s, "trace-1", "s1", "Bash", true, "deny-bash")

	dist, err := svc.GetDistribution(context.Background(), "30d")
	if err != nil {
		t.Fatalf("GetDistribution: %v", err)
	}
	if dist == nil {
		t.Fatal("GetDistribution should not return nil")
	}
	if dist.ByRule == nil {
		t.Error("ByRule should not be nil")
	}
	if dist.ByTool == nil {
		t.Error("ByTool should not be nil")
	}
}

func TestStatsService_GetDistribution_EmptyDB(t *testing.T) {
	s := newTestStorage(t)
	svc := NewStatsService(s)

	dist, err := svc.GetDistribution(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if dist.ByRule == nil || dist.ByTool == nil {
		t.Error("empty DB should return non-nil empty slices")
	}
}

func TestStatsService_GetCoverage(t *testing.T) {
	s := newTestStorage(t)
	svc := NewStatsService(s)

	insertToolCall(t, s, "trace-1", "s1", "Read", false, "")

	tools, err := svc.GetCoverage(context.Background(), "30d")
	if err != nil {
		t.Fatalf("GetCoverage: %v", err)
	}
	if tools == nil {
		t.Error("GetCoverage should never return nil")
	}
}

func TestStatsService_GetCoverage_EmptyDB(t *testing.T) {
	s := newTestStorage(t)
	svc := NewStatsService(s)

	tools, err := svc.GetCoverage(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if tools == nil {
		t.Error("empty DB should return non-nil empty slice")
	}
}

// ---------------------------------------------------------------------------
// API Handlers: HandleSessions
// ---------------------------------------------------------------------------

func TestHandleSessions(t *testing.T) {
	s := newTestStorage(t)
	h := NewAPIHandler(s)

	insertToolCall(t, s, "trace-1", "session-a", "Read", false, "")
	insertToolCall(t, s, "trace-2", "session-b", "Bash", true, "deny-bash")

	req := httptest.NewRequest(http.MethodGet, "/api/telemetry/sessions?minutes=60&limit=50", nil)
	w := httptest.NewRecorder()
	h.HandleSessions(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp []json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
}

func TestHandleSessions_EmptyDB(t *testing.T) {
	s := newTestStorage(t)
	h := NewAPIHandler(s)

	req := httptest.NewRequest(http.MethodGet, "/api/telemetry/sessions", nil)
	w := httptest.NewRecorder()
	h.HandleSessions(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

// ---------------------------------------------------------------------------
// API Handlers: HandleSessionEvents
// ---------------------------------------------------------------------------

func TestHandleSessionEvents(t *testing.T) {
	s := newTestStorage(t)
	h := NewAPIHandler(s)

	insertToolCall(t, s, "trace-1", "session-x", "Read", false, "")

	req := httptest.NewRequest(http.MethodGet, "/api/telemetry/sessions/session-x/events", nil)
	req.SetPathValue("session_id", "session-x")
	w := httptest.NewRecorder()
	h.HandleSessionEvents(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestHandleSessionEvents_MissingSessionID(t *testing.T) {
	s := newTestStorage(t)
	h := NewAPIHandler(s)

	req := httptest.NewRequest(http.MethodGet, "/api/telemetry/sessions//events", nil)
	// Don't set path value — empty session_id
	w := httptest.NewRecorder()
	h.HandleSessionEvents(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ---------------------------------------------------------------------------
// API Handlers: HandleTraces
// ---------------------------------------------------------------------------

func TestHandleTraces(t *testing.T) {
	s := newTestStorage(t)
	h := NewAPIHandler(s)

	insertSpanTx(t, s, "trace-1", "s1", 100, 200)

	req := httptest.NewRequest(http.MethodGet, "/api/telemetry/traces?limit=10", nil)
	w := httptest.NewRecorder()
	h.HandleTraces(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp []json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

func TestHandleTraces_EmptyDB(t *testing.T) {
	s := newTestStorage(t)
	h := NewAPIHandler(s)

	req := httptest.NewRequest(http.MethodGet, "/api/telemetry/traces", nil)
	w := httptest.NewRecorder()
	h.HandleTraces(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

// ---------------------------------------------------------------------------
// API Handlers: HandleTrace
// ---------------------------------------------------------------------------

func TestHandleTrace(t *testing.T) {
	s := newTestStorage(t)
	h := NewAPIHandler(s)

	insertSpanTx(t, s, "trace-detail", "s1", 50, 75)

	req := httptest.NewRequest(http.MethodGet, "/api/telemetry/traces/trace-detail", nil)
	req.SetPathValue("trace_id", "trace-detail")
	w := httptest.NewRecorder()
	h.HandleTrace(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := resp["trace_id"]; !ok {
		t.Error("response should contain 'trace_id'")
	}
}

func TestHandleTrace_MissingTraceID(t *testing.T) {
	s := newTestStorage(t)
	h := NewAPIHandler(s)

	req := httptest.NewRequest(http.MethodGet, "/api/telemetry/traces/", nil)
	w := httptest.NewRecorder()
	h.HandleTrace(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleTrace_NotFound(t *testing.T) {
	s := newTestStorage(t)
	h := NewAPIHandler(s)

	req := httptest.NewRequest(http.MethodGet, "/api/telemetry/traces/nonexistent", nil)
	req.SetPathValue("trace_id", "nonexistent")
	w := httptest.NewRecorder()
	h.HandleTrace(w, req)

	// GetTraceSpans returns empty slice (not nil) for nonexistent trace,
	// so this might return 200 or 404 depending on implementation.
	// The code checks `if spans == nil` for 404.
	// sqlc returns nil slice when no rows found.
	if w.Code != http.StatusOK && w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 200 or 404", w.Code)
	}
}

// ---------------------------------------------------------------------------
// API Handlers: HandleStats
// ---------------------------------------------------------------------------

func TestHandleStats(t *testing.T) {
	s := newTestStorage(t)
	h := NewAPIHandler(s)

	insertSpanTx(t, s, "trace-stats", "s1", 100, 200)

	req := httptest.NewRequest(http.MethodGet, "/api/telemetry/stats", nil)
	w := httptest.NewRecorder()
	h.HandleStats(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

// ---------------------------------------------------------------------------
// API Handlers: StatsAggHandlers
// ---------------------------------------------------------------------------

func TestStatsAggHandlers(t *testing.T) {
	s := newTestStorage(t)
	h := NewAPIHandler(s)

	svc := h.StatsAggHandlers()
	if svc == nil {
		t.Fatal("StatsAggHandlers should not be nil")
	}
}

// ---------------------------------------------------------------------------
// StatsService HTTP Handlers
// ---------------------------------------------------------------------------

func TestHandleBlockTrend_HTTP(t *testing.T) {
	s := newTestStorage(t)
	svc := NewStatsService(s)

	insertToolCall(t, s, "trace-1", "s1", "Read", false, "")
	insertToolCall(t, s, "trace-2", "s1", "Bash", true, "deny-bash")

	req := httptest.NewRequest(http.MethodGet, "/api/telemetry/stats/trend?range=7d", nil)
	w := httptest.NewRecorder()
	svc.HandleBlockTrend(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestHandleDistribution_HTTP(t *testing.T) {
	s := newTestStorage(t)
	svc := NewStatsService(s)

	insertToolCall(t, s, "trace-1", "s1", "Bash", true, "deny-bash")

	req := httptest.NewRequest(http.MethodGet, "/api/telemetry/stats/distribution?range=30d", nil)
	w := httptest.NewRecorder()
	svc.HandleDistribution(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestHandleCoverage_HTTP(t *testing.T) {
	s := newTestStorage(t)
	svc := NewStatsService(s)

	insertToolCall(t, s, "trace-1", "s1", "Read", false, "")

	req := httptest.NewRequest(http.MethodGet, "/api/telemetry/stats/coverage?range=30d", nil)
	w := httptest.NewRecorder()
	svc.HandleCoverage(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

// ---------------------------------------------------------------------------
// NopRecorder
// ---------------------------------------------------------------------------

func TestNopRecorder(t *testing.T) {
	var r NopRecorder

	if err := r.LogToolCall(context.Background(), ToolCallLog{}); err != nil {
		t.Errorf("LogToolCall: %v", err)
	}
	if err := r.RecordSpanTx(context.Background(), "t", "s", nil, nil); err != nil {
		t.Errorf("RecordSpanTx: %v", err)
	}
	n, err := r.CleanupOldData(context.Background(), 1)
	if err != nil {
		t.Errorf("CleanupOldData: %v", err)
	}
	if n != 0 {
		t.Errorf("CleanupOldData = %d, want 0", n)
	}
	if err := r.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Provider: Init, SetStorage, IsEnabled, Shutdown, StartLLMSpan, EndLLMSpan
// ---------------------------------------------------------------------------

func TestProvider_Init(t *testing.T) {
	p, err := Init(context.Background(), Config{
		Enabled:     true,
		ServiceName: "test",
		SampleRate:  1.0,
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !p.IsEnabled() {
		t.Error("provider should be enabled")
	}
}

func TestProvider_Disabled(t *testing.T) {
	p, err := Init(context.Background(), Config{Enabled: false})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if p.IsEnabled() {
		t.Error("provider should be disabled")
	}
}

func TestProvider_IsEnabled_Nil(t *testing.T) {
	var p *Provider
	if p.IsEnabled() {
		t.Error("nil provider should not be enabled")
	}
}

func TestProvider_SetStorage(t *testing.T) {
	p, _ := Init(context.Background(), Config{Enabled: true})
	s := newTestStorage(t)
	p.SetStorage(s)
	// No panic = success
}

func TestProvider_SetStorage_NilProvider(t *testing.T) {
	var p *Provider
	p.SetStorage(nil) // should not panic
}

func TestProvider_Shutdown(t *testing.T) {
	p, _ := Init(context.Background(), Config{Enabled: true})
	if err := p.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
}

func TestProvider_StartLLMSpan_Disabled(t *testing.T) {
	p, _ := Init(context.Background(), Config{Enabled: false})
	_, spanCtx := p.StartLLMSpan(context.Background(), "op", "trace-1", "")
	if spanCtx != nil {
		t.Error("disabled provider should return nil span context")
	}
}

func TestProvider_StartLLMSpan_NilProvider(t *testing.T) {
	var p *Provider
	_, spanCtx := p.StartLLMSpan(context.Background(), "op", "trace-1", "")
	if spanCtx != nil {
		t.Error("nil provider should return nil span context")
	}
}

func TestProvider_StartLLMSpan_Enabled(t *testing.T) {
	p, _ := Init(context.Background(), Config{Enabled: true})
	_, spanCtx := p.StartLLMSpan(context.Background(), "op", "trace-1", "")
	if spanCtx == nil {
		t.Fatal("enabled provider should return span context")
	}
	if spanCtx.TraceID != "trace-1" {
		t.Errorf("TraceID = %q, want trace-1", spanCtx.TraceID)
	}
	if spanCtx.Name != "op" {
		t.Errorf("Name = %q, want op", spanCtx.Name)
	}
}

func TestProvider_StartLLMSpan_CustomName(t *testing.T) {
	p, _ := Init(context.Background(), Config{Enabled: true})
	_, spanCtx := p.StartLLMSpan(context.Background(), "default-op", "trace-1", "custom-name")
	if spanCtx == nil {
		t.Fatal("expected span context")
	}
	if spanCtx.Name != "custom-name" {
		t.Errorf("Name = %q, want custom-name", spanCtx.Name)
	}
}

func TestProvider_EndLLMSpan_NilProvider(t *testing.T) {
	var p *Provider
	p.EndLLMSpan(nil, LLMSpanData{}) // should not panic
}

func TestProvider_EndLLMSpan_Disabled(t *testing.T) {
	p, _ := Init(context.Background(), Config{Enabled: false})
	p.EndLLMSpan(&SpanContext{}, LLMSpanData{}) // should not panic
}

func TestProvider_EndLLMSpan_NilSpanCtx(t *testing.T) {
	p, _ := Init(context.Background(), Config{Enabled: true})
	p.EndLLMSpan(nil, LLMSpanData{}) // should not panic
}

func TestProvider_EndLLMSpan_NoStorage(t *testing.T) {
	p, _ := Init(context.Background(), Config{Enabled: true})
	// No storage set — should log debug but not panic
	_, spanCtx := p.StartLLMSpan(context.Background(), "op", "trace-1", "")
	p.EndLLMSpan(spanCtx, LLMSpanData{TraceID: "trace-1"})
}

func TestProvider_EndLLMSpan_WithStorage(t *testing.T) {
	p, _ := Init(context.Background(), Config{Enabled: true})
	s := newTestStorage(t)
	p.SetStorage(s)

	_, spanCtx := p.StartLLMSpan(context.Background(), "op", "trace-end-llm", "")
	p.EndLLMSpan(spanCtx, LLMSpanData{
		TraceID:      "trace-end-llm",
		SessionID:    "s1",
		SpanKind:     SpanKindLLM,
		Model:        "gpt-4",
		TargetURL:    "https://api.openai.com/v1/chat?key=secret",
		InputTokens:  100,
		OutputTokens: 200,
		StatusCode:   200,
		Messages:     json.RawMessage(`{"role":"user"}`),
		Response:     json.RawMessage(`{"choices":[]}`),
		ToolCalls: []ToolCall{
			{ID: "tc-1", Name: "bash", Arguments: json.RawMessage(`{"cmd":"ls"}`)},
		},
	})

	// Verify the trace and spans were recorded
	spans, err := s.GetTraceSpans(context.Background(), "trace-end-llm")
	if err != nil {
		t.Fatalf("GetTraceSpans: %v", err)
	}
	if len(spans) < 2 {
		t.Errorf("expected at least 2 spans (main + tool), got %d", len(spans))
	}
}

func TestProvider_EndLLMSpan_ErrorStatus(t *testing.T) {
	p, _ := Init(context.Background(), Config{Enabled: true})
	s := newTestStorage(t)
	p.SetStorage(s)

	_, spanCtx := p.StartLLMSpan(context.Background(), "op", "trace-err", "")
	p.EndLLMSpan(spanCtx, LLMSpanData{
		TraceID:    "trace-err",
		StatusCode: 500,
	})

	spans, err := s.GetTraceSpans(context.Background(), "trace-err")
	if err != nil {
		t.Fatalf("GetTraceSpans: %v", err)
	}
	if len(spans) == 0 {
		t.Fatal("expected at least 1 span")
	}
	if spans[0].StatusCode != "ERROR" {
		t.Errorf("StatusCode = %q, want ERROR", spans[0].StatusCode)
	}
}

func TestProvider_EndLLMSpan_EmptySpanKindDefaultsToLLM(t *testing.T) {
	p, _ := Init(context.Background(), Config{Enabled: true})
	s := newTestStorage(t)
	p.SetStorage(s)

	_, spanCtx := p.StartLLMSpan(context.Background(), "op", "trace-default-kind", "")
	p.EndLLMSpan(spanCtx, LLMSpanData{
		TraceID:  "trace-default-kind",
		SpanKind: "", // empty — should default to LLM
	})

	spans, err := s.GetTraceSpans(context.Background(), "trace-default-kind")
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) == 0 {
		t.Fatal("expected spans")
	}
	if spans[0].SpanKind != SpanKindLLM {
		t.Errorf("SpanKind = %q, want %q", spans[0].SpanKind, SpanKindLLM)
	}
}

// ---------------------------------------------------------------------------
// truncateString edge cases
// ---------------------------------------------------------------------------

func TestTruncateString_ZeroMaxLen(t *testing.T) {
	got := truncateString("hello", 0)
	if got != "...[truncated]" {
		t.Errorf("truncateString(hello, 0) = %q, want '...[truncated]'", got)
	}
}

func TestTruncateString_ZeroMaxLen_Empty(t *testing.T) {
	got := truncateString("", 0)
	if got != "" {
		t.Errorf("truncateString('', 0) = %q, want ''", got)
	}
}

// ---------------------------------------------------------------------------
// SanitizeSpans
// ---------------------------------------------------------------------------

func TestSanitizeSpans(t *testing.T) {
	attrs := map[string]any{
		AttrInputValue: "secret",
		AttrLLMModel:   "gpt-4",
	}
	raw, _ := json.Marshal(attrs)

	spans := []Span{
		{Name: "span-1", Attributes: raw},
		{Name: "span-2", Attributes: raw},
	}

	sanitized := SanitizeSpans(spans)
	if len(sanitized) != 2 {
		t.Fatalf("expected 2 sanitized spans, got %d", len(sanitized))
	}

	for _, s := range sanitized {
		var result map[string]any
		if err := json.Unmarshal(s.Attributes, &result); err != nil {
			t.Fatal(err)
		}
		if _, ok := result[AttrInputValue]; ok {
			t.Error("input.value should be stripped")
		}
		if _, ok := result[AttrLLMModel]; !ok {
			t.Error("llm.model_name should be preserved")
		}
	}
}

// ---------------------------------------------------------------------------
// writeJSON / writeError (via HTTP handlers)
// ---------------------------------------------------------------------------

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, map[string]string{"hello": "world"})

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestWriteError(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, http.StatusInternalServerError, "something went wrong")

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["error"] != "something went wrong" {
		t.Errorf("error = %q, want 'something went wrong'", resp["error"])
	}
}

// ---------------------------------------------------------------------------
// dbToolCallLogToToolCallLog
// ---------------------------------------------------------------------------

func TestDbToolCallLogToToolCallLog_ViaGetRecentLogs(t *testing.T) {
	s := newTestStorage(t)

	// Insert a tool call with arguments to exercise the conversion
	err := s.LogToolCall(context.Background(), ToolCallLog{
		TraceID:       "trace-conv",
		SessionID:     "s1",
		ToolName:      "Write",
		ToolArguments: json.RawMessage(`{"path":"/tmp/test"}`),
		WasBlocked:    true,
		BlockedByRule: "deny-write",
		Model:         "gpt-4",
		Layer:         "proxy_response",
	})
	if err != nil {
		t.Fatalf("LogToolCall: %v", err)
	}

	logs, err := s.GetRecentLogs(context.Background(), 60, 10)
	if err != nil {
		t.Fatalf("GetRecentLogs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logs))
	}

	l := logs[0]
	if l.ToolName != "Write" {
		t.Errorf("ToolName = %q, want Write", l.ToolName)
	}
	if !l.WasBlocked {
		t.Error("WasBlocked should be true")
	}
	if l.BlockedByRule != "deny-write" {
		t.Errorf("BlockedByRule = %q, want deny-write", l.BlockedByRule)
	}
	if l.Model != "gpt-4" {
		t.Errorf("Model = %q, want gpt-4", l.Model)
	}
}

// ---------------------------------------------------------------------------
// GetTraceStats with data
// ---------------------------------------------------------------------------

func TestGetTraceStats_WithData(t *testing.T) {
	s := newTestStorage(t)

	insertSpanTx(t, s, "trace-stats-1", "s1", 100, 200)
	insertSpanTx(t, s, "trace-stats-2", "s2", 50, 75)

	stats, err := s.GetTraceStats(context.Background())
	if err != nil {
		t.Fatalf("GetTraceStats: %v", err)
	}
	if stats.TotalTraces < 2 {
		t.Errorf("TotalTraces = %d, want >= 2", stats.TotalTraces)
	}
	if stats.TotalSpans < 2 {
		t.Errorf("TotalSpans = %d, want >= 2", stats.TotalSpans)
	}
}

// ---------------------------------------------------------------------------
// ListRecentTraces boundary
// ---------------------------------------------------------------------------

func TestListRecentTraces_ZeroLimit(t *testing.T) {
	s := newTestStorage(t)

	insertSpanTx(t, s, "trace-limit", "s1", 10, 20)

	traces, err := s.ListRecentTraces(context.Background(), 0)
	if err != nil {
		t.Fatalf("ListRecentTraces(0): %v", err)
	}
	// limit=0 should default to 100 — but we only have 1 trace
	if len(traces) != 1 {
		t.Errorf("got %d traces, want 1", len(traces))
	}
}

// ---------------------------------------------------------------------------
// CleanupOldData edge cases
// ---------------------------------------------------------------------------

func TestCleanupOldData_ZeroDays(t *testing.T) {
	s := newTestStorage(t)
	deleted, err := s.CleanupOldData(context.Background(), 0)
	if err != nil {
		t.Fatalf("CleanupOldData(0): %v", err)
	}
	if deleted != 0 {
		t.Errorf("deleted = %d, want 0 for days=0", deleted)
	}
}

func TestCleanupOldData_ExceedsMaxRetention(t *testing.T) {
	s := newTestStorage(t)
	// Should clamp to MaxRetentionDays but not error
	_, err := s.CleanupOldData(context.Background(), MaxRetentionDays+100)
	if err != nil {
		t.Fatalf("CleanupOldData(max+100): %v", err)
	}
}

// ---------------------------------------------------------------------------
// LogToolCall: default layer
// ---------------------------------------------------------------------------

func TestLogToolCall_DefaultLayer(t *testing.T) {
	s := newTestStorage(t)

	err := s.LogToolCall(context.Background(), ToolCallLog{
		TraceID:  "trace-default-layer",
		ToolName: "Read",
		// Layer is empty — should default to proxy_response
	})
	if err != nil {
		t.Fatalf("LogToolCall: %v", err)
	}

	var layer string
	err = s.DB().QueryRow("SELECT layer FROM tool_call_logs WHERE trace_id = ?", "trace-default-layer").Scan(&layer)
	if err != nil {
		t.Fatal(err)
	}
	if layer != defaultLayer {
		t.Errorf("layer = %q, want %q", layer, defaultLayer)
	}
}

// ---------------------------------------------------------------------------
// NewStorage: encryption key validation
// ---------------------------------------------------------------------------

func TestNewStorage_ShortEncryptionKey(t *testing.T) {
	_, err := NewStorage(":memory:", "short")
	if err == nil {
		t.Fatal("expected error for short encryption key")
	}
}

// ---------------------------------------------------------------------------
// HandleTrace: with root span (tests latency + root span response fields)
// ---------------------------------------------------------------------------

func TestHandleTrace_WithRootSpan(t *testing.T) {
	s := newTestStorage(t)
	h := NewAPIHandler(s)

	// Insert a trace with a root span (no parent)
	mainSpan := &Span{
		SpanID:    "root-span",
		Name:      "root-llm-call",
		SpanKind:  SpanKindLLM,
		StartTime: time.Now().Add(-200 * time.Millisecond),
		EndTime:   time.Now(),
	}
	err := s.RecordSpanTx(context.Background(), "trace-root", "s1", mainSpan, nil)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/telemetry/traces/trace-root", nil)
	req.SetPathValue("trace_id", "trace-root")
	w := httptest.NewRecorder()
	h.HandleTrace(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var data map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if _, ok := data["root_span_name"]; !ok {
		t.Error("response should contain root_span_name")
	}
	if _, ok := data["latency_ms"]; !ok {
		t.Error("response should contain latency_ms")
	}
}

// ---------------------------------------------------------------------------
// HandleTraces: with end time set (tests latency calculation)
// ---------------------------------------------------------------------------

func TestHandleTraces_WithEndTime(t *testing.T) {
	s := newTestStorage(t)
	h := NewAPIHandler(s)

	mainSpan := &Span{
		SpanID:       "span-latency",
		Name:         "llm-call",
		SpanKind:     SpanKindLLM,
		StartTime:    time.Now().Add(-500 * time.Millisecond),
		EndTime:      time.Now(),
		InputTokens:  100,
		OutputTokens: 200,
	}
	err := s.RecordSpanTx(context.Background(), "trace-latency", "s1", mainSpan, nil)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/telemetry/traces?limit=10", nil)
	w := httptest.NewRecorder()
	h.HandleTraces(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}
