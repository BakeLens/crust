package telemetry

import (
	"context"
	"io"

	"github.com/BakeLens/crust/internal/types"
)

// Recorder is the write-only interface for telemetry recording.
// *Storage satisfies this interface. Use NopRecorder for builds
// without a database (e.g. libcrust/iOS).
type Recorder interface {
	LogToolCall(ctx context.Context, toolLog ToolCallLog) error
	RecordSpanTx(ctx context.Context, traceID types.TraceID, sessionID types.SessionID, mainSpan *Span, toolSpans []*Span) error
	CleanupOldData(ctx context.Context, days int) (int64, error)
	io.Closer
}

// NopRecorder is a no-op Recorder for environments without a database.
type NopRecorder struct{}

func (NopRecorder) LogToolCall(context.Context, ToolCallLog) error { return nil }
func (NopRecorder) RecordSpanTx(context.Context, types.TraceID, types.SessionID, *Span, []*Span) error {
	return nil
}
func (NopRecorder) CleanupOldData(context.Context, int) (int64, error) { return 0, nil }
func (NopRecorder) Close() error                                       { return nil }
