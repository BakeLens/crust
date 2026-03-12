package telemetry

import (
	"encoding/json"
	"time"

	"github.com/BakeLens/crust/internal/types"
)

// Span represents a span record (wraps db.Span for compatibility)
type Span struct {
	ID            int64           `json:"id"`
	TraceRowID    int64           `json:"trace_rowid"`
	SpanID        types.SpanID    `json:"span_id"`
	ParentSpanID  types.SpanID    `json:"parent_span_id,omitempty"`
	Name          string          `json:"name"`
	SpanKind      string          `json:"span_kind"`
	StartTime     time.Time       `json:"start_time"`
	EndTime       time.Time       `json:"end_time"`
	Attributes    json.RawMessage `json:"attributes,omitempty"`
	Events        json.RawMessage `json:"events,omitempty"`
	InputTokens   int64           `json:"input_tokens"`
	OutputTokens  int64           `json:"output_tokens"`
	StatusCode    string          `json:"status_code"`
	StatusMessage string          `json:"status_message,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
}

// ToolCallLog represents a logged tool call
type ToolCallLog struct {
	ID            int64           `json:"id"`
	Timestamp     time.Time       `json:"timestamp"`
	TraceID       types.TraceID   `json:"trace_id"`
	SessionID     types.SessionID `json:"session_id,omitempty"`
	ToolName      string          `json:"tool_name"`
	ToolArguments json.RawMessage `json:"tool_arguments,omitempty"`
	APIType       types.APIType   `json:"api_type"`
	WasBlocked    bool            `json:"was_blocked"`
	BlockedByRule string          `json:"blocked_by_rule,omitempty"`
	Model         string          `json:"model,omitempty"`
	Layer         string          `json:"layer,omitempty"`
	Protocol      string          `json:"protocol,omitempty"`
	Direction     string          `json:"direction,omitempty"`
	Method        string          `json:"method,omitempty"`
	BlockType     string          `json:"block_type,omitempty"`
}
