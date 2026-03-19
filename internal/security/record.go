package security

import (
	"context"
	"time"

	"github.com/BakeLens/crust/internal/eventlog"
	"github.com/BakeLens/crust/internal/telemetry"
)

// storageSink implements eventlog.Sink by writing to the telemetry database.
type storageSink struct {
	storage telemetry.Recorder
}

func (s storageSink) LogEvent(event eventlog.Event) {
	if s.storage == nil {
		return
	}

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
	if err := s.storage.LogToolCall(ctx, tcLog); err != nil {
		log.Warn("Failed to log security event: %v", err)
	}
}

// initEventSink registers the storage sink with eventlog.
// Called by Manager.Init after storage is ready.
func initEventSink(storage telemetry.Recorder) {
	eventlog.SetSink(storageSink{storage: storage})
}
