package security

import (
	"context"
	"encoding/json"

	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/types"
)

// Layer constants for telemetry tracking.
const (
	LayerL0       = "L0"        // Request-side blocking (Layer 0)
	LayerL1       = "L1"        // Response-side blocking (Layer 1, non-streaming)
	LayerL1Stream = "L1_stream" // Response-side streaming (unbuffered, log-only)
	LayerL1Buffer = "L1_buffer" // Response-side buffered streaming
)

// Event represents a tool call evaluation event at any layer.
type Event struct {
	Layer      string // LayerL0, LayerL1, LayerL1Stream, LayerL1Buffer
	TraceID    types.TraceID
	SessionID  types.SessionID
	ToolName   string
	Arguments  json.RawMessage
	APIType    types.APIType
	Model      string
	WasBlocked bool
	RuleName   string
}

// RecordEvent logs a security event to BOTH in-memory metrics AND the database.
// This is the single entry point for recording security events across all layers.
func RecordEvent(event Event) {
	log.Debug("RecordEvent: layer=%s tool=%s blocked=%v rule=%s", event.Layer, event.ToolName, event.WasBlocked, event.RuleName)

	m := globalMetrics

	// Update in-memory metrics.
	// TotalToolCalls is only incremented alongside a sub-counter to preserve:
	//   TotalToolCalls == Layer0Blocks + Layer1Blocks + Layer1Allowed
	// L0 events are only emitted when blocked; non-blocked L0 events are
	// silently dropped from metrics (they shouldn't occur in practice).
	switch event.Layer {
	case LayerL0:
		if event.WasBlocked {
			m.Layer0Blocks.Add(1)
			m.TotalToolCalls.Add(1)
		}
	case LayerL1, LayerL1Stream, LayerL1Buffer:
		if event.WasBlocked {
			m.Layer1Blocks.Add(1)
		} else {
			m.Layer1Allowed.Add(1)
		}
		m.TotalToolCalls.Add(1)
	}

	// Log to database
	interceptor := GetGlobalInterceptor()
	if interceptor == nil {
		return
	}
	storage := interceptor.GetStorage()
	if storage == nil {
		return
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
		Layer:         event.Layer,
	}

	if err := storage.LogToolCall(context.Background(), tcLog); err != nil {
		log.Warn("Failed to log security event: %v", err)
	}
}
