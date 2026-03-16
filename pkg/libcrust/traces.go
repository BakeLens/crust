//go:build libcrust

package libcrust

import (
	"github.com/BakeLens/crust/internal/types"
)

// TraceSummary is the wire format for trace listing.
type TraceSummary struct {
	TraceID      string `json:"trace_id"`
	SessionID    string `json:"session_id,omitempty"`
	StartTime    string `json:"start_time"`
	EndTime      string `json:"end_time"`
	SpanCount    int    `json:"span_count"`
	TotalTokens  int64  `json:"total_tokens"`
	LatencyMs    int64  `json:"latency_ms"`
	RootSpanName string `json:"root_span_name,omitempty"`
	RootSpanKind string `json:"root_span_kind,omitempty"`
}

// GetTraces returns recent traces as a JSON array.
// limit: max rows (default 50, max 1000).
func GetTraces(limit int) string {
	s := getStorage()
	if s == nil {
		return "[]"
	}
	if limit <= 0 {
		limit = 50
	}

	traces, err := s.ListRecentTraces(ctx(), limit)
	if err != nil {
		return errJSON(err)
	}

	// Enrich with span counts and token totals.
	summaries := make([]TraceSummary, 0, len(traces))
	for _, t := range traces {
		spans, _ := s.GetTraceSpans(ctx(), t.TraceID)

		var totalTokens int64
		var rootName, rootKind string
		for _, sp := range spans {
			totalTokens += sp.InputTokens + sp.OutputTokens
			if string(sp.ParentSpanID) == "" {
				rootName = sp.Name
				rootKind = sp.SpanKind
			}
		}

		latencyMs := int64(0)
		if !t.StartTime.IsZero() && !t.EndTime.IsZero() {
			latencyMs = t.EndTime.Sub(t.StartTime).Milliseconds()
		}

		summaries = append(summaries, TraceSummary{
			TraceID:      string(t.TraceID),
			SessionID:    string(t.SessionID),
			StartTime:    t.StartTime.Format("2006-01-02T15:04:05Z07:00"),
			EndTime:      t.EndTime.Format("2006-01-02T15:04:05Z07:00"),
			SpanCount:    len(spans),
			TotalTokens:  totalTokens,
			LatencyMs:    latencyMs,
			RootSpanName: rootName,
			RootSpanKind: rootKind,
		})
	}

	return mustJSON(summaries)
}

// GetTraceDetail returns a single trace with all its spans as JSON.
func GetTraceDetail(traceID string) string {
	s := getStorage()
	if s == nil {
		return errJSON(errNotInit)
	}

	spans, err := s.GetTraceSpans(ctx(), types.TraceID(traceID))
	if err != nil {
		return errJSON(err)
	}

	return mustJSON(map[string]any{
		"trace_id": traceID,
		"spans":    spans,
	})
}

// GetTraceStats returns aggregate trace/span statistics as JSON.
func GetTraceStats() string {
	s := getStorage()
	if s == nil {
		return errJSON(errNotInit)
	}

	stats, err := s.GetTraceStats(ctx())
	if err != nil {
		return errJSON(err)
	}
	return mustJSON(stats)
}
