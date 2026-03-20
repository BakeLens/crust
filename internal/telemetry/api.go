//go:build !libcrust

package telemetry

import (
	"net/http"
	"strconv"

	"github.com/BakeLens/crust/internal/api"
	"github.com/BakeLens/crust/internal/types"
)

// APIHandler handles HTTP API requests for telemetry.
type APIHandler struct {
	storage *Storage
	stats   *StatsService
}

// NewAPIHandler creates a new telemetry API handler.
func NewAPIHandler(storage *Storage) *APIHandler {
	return &APIHandler{
		storage: storage,
		stats:   NewStatsService(storage),
	}
}

// StatsAggHandlers returns the StatsService for registering its net/http handlers.
func (h *APIHandler) StatsAggHandlers() *StatsService {
	return h.stats
}

func queryInt(r *http.Request, key string, defaultVal, maxVal int) int {
	s := r.URL.Query().Get(key)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 1 {
		return defaultVal
	}
	if v > maxVal {
		return maxVal
	}
	return v
}

// HandleSessions handles GET /api/telemetry/sessions.
func (h *APIHandler) HandleSessions(w http.ResponseWriter, r *http.Request) {
	minutes := queryInt(r, "minutes", 60, 10080)
	limit := queryInt(r, "limit", 50, 200)

	sessions, err := h.storage.GetSessions(r.Context(), minutes, limit)
	if err != nil {
		api.Error(w, http.StatusInternalServerError, "Failed to get sessions")
		return
	}
	if sessions == nil {
		sessions = []SessionSummary{}
	}
	api.Success(w, sessions)
}

// HandleSessionEvents handles GET /api/telemetry/sessions/{session_id}/events.
func (h *APIHandler) HandleSessionEvents(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("session_id")
	if sessionID == "" {
		api.Error(w, http.StatusBadRequest, "Session ID required")
		return
	}

	limit := queryInt(r, "limit", 50, 200)

	events, err := h.storage.GetSessionEvents(r.Context(), types.SessionID(sessionID), limit)
	if err != nil {
		api.Error(w, http.StatusInternalServerError, "Failed to get session events")
		return
	}
	if events == nil {
		events = []ToolCallLog{}
	}
	api.Success(w, SanitizeToolCallLogs(events))
}

// HandleTraces handles GET /api/telemetry/traces.
func (h *APIHandler) HandleTraces(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 100, 1000)

	traces, err := h.storage.ListRecentTraces(r.Context(), limit)
	if err != nil {
		api.Error(w, http.StatusInternalServerError, "Failed to list traces")
		return
	}

	if traces == nil {
		traces = []Trace{}
	}

	type TraceWithStats struct {
		Trace
		SpanCount   int   `json:"span_count"`
		TotalTokens int64 `json:"total_tokens"`
		LatencyMs   int64 `json:"latency_ms"`
	}

	result := make([]TraceWithStats, 0, len(traces))
	for _, trace := range traces {
		spans, err := h.storage.GetTraceSpans(r.Context(), trace.TraceID)
		if err != nil {
			log.Debug("Failed to get spans for trace %s: %v", trace.TraceID, err)
		}
		var totalTokens int64
		for _, span := range spans {
			totalTokens += span.InputTokens + span.OutputTokens
		}

		var latencyMs int64
		if !trace.EndTime.IsZero() && !trace.StartTime.IsZero() {
			latencyMs = trace.EndTime.Sub(trace.StartTime).Milliseconds()
		}

		result = append(result, TraceWithStats{
			Trace:       trace,
			SpanCount:   len(spans),
			TotalTokens: totalTokens,
			LatencyMs:   latencyMs,
		})
	}

	api.Success(w, result)
}

// HandleTrace handles GET /api/telemetry/traces/{trace_id}.
func (h *APIHandler) HandleTrace(w http.ResponseWriter, r *http.Request) {
	traceID := r.PathValue("trace_id")
	if traceID == "" {
		api.Error(w, http.StatusBadRequest, "Trace ID required")
		return
	}

	spans, err := h.storage.GetTraceSpans(r.Context(), types.TraceID(traceID))
	if err != nil {
		api.Error(w, http.StatusInternalServerError, "Failed to get spans")
		return
	}

	if spans == nil {
		api.Error(w, http.StatusNotFound, "Trace not found")
		return
	}

	var totalInputTokens, totalOutputTokens int64
	for _, span := range spans {
		totalInputTokens += span.InputTokens
		totalOutputTokens += span.OutputTokens
	}

	sanitizedSpans := SanitizeSpans(spans)

	var rootSpan *Span
	for i := range sanitizedSpans {
		if sanitizedSpans[i].ParentSpanID.IsEmpty() {
			rootSpan = &sanitizedSpans[i]
			break
		}
	}

	var latencyMs int64
	if rootSpan != nil && !rootSpan.EndTime.IsZero() && !rootSpan.StartTime.IsZero() {
		latencyMs = rootSpan.EndTime.Sub(rootSpan.StartTime).Milliseconds()
	}

	response := map[string]any{
		"trace_id":            traceID,
		"spans":               sanitizedSpans,
		"span_count":          len(spans),
		"total_input_tokens":  totalInputTokens,
		"total_output_tokens": totalOutputTokens,
		"total_tokens":        totalInputTokens + totalOutputTokens,
		"latency_ms":          latencyMs,
	}

	if rootSpan != nil {
		response["root_span_name"] = rootSpan.Name
		response["root_span_kind"] = rootSpan.SpanKind
	}

	api.Success(w, response)
}

// HandleStats handles GET /api/telemetry/stats.
func (h *APIHandler) HandleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.storage.GetTraceStats(r.Context())
	if err != nil {
		api.Error(w, http.StatusInternalServerError, "Failed to get stats")
		return
	}

	api.Success(w, stats)
}
