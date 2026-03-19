package monitor

import (
	"encoding/json"
	"time"

	"github.com/BakeLens/crust/internal/eventlog"
)

// eventPayload is the JSON shape for event changes, matching the ToolCallLog
// structure that the GUI expects. Fields mirror telemetry.ToolCallLog.
type eventPayload struct {
	ToolName   string          `json:"tool_name"`
	WasBlocked bool            `json:"was_blocked"`
	RuleName   string          `json:"blocked_by_rule,omitempty"`
	Layer      string          `json:"layer"`
	Protocol   string          `json:"protocol,omitempty"`
	Direction  string          `json:"direction,omitempty"`
	Method     string          `json:"method,omitempty"`
	BlockType  string          `json:"block_type,omitempty"`
	APIType    string          `json:"api_type,omitempty"`
	Model      string          `json:"model,omitempty"`
	TraceID    string          `json:"trace_id,omitempty"`
	SessionID  string          `json:"session_id,omitempty"`
	Arguments  json.RawMessage `json:"tool_arguments,omitempty"`
	Timestamp  time.Time       `json:"timestamp"`
}

// runEventRelay subscribes to eventlog and relays events to the change channel.
// Events are delivered in real-time with no polling delay.
func (m *Monitor) runEventRelay() {
	defer m.wg.Done()

	id, ch, err := eventlog.Subscribe(128)
	if err != nil {
		log.Warn("event subscribe failed: %v", err)
		// Fall back: no event relay. Agent/session/protect still work.
		<-m.stop
		return
	}
	defer eventlog.Unsubscribe(id)

	for {
		select {
		case <-m.stop:
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			m.emit(ChangeEvent, eventToPayload(event))
		}
	}
}

// eventToPayload converts an eventlog.Event to the JSON payload format.
func eventToPayload(e eventlog.Event) eventPayload {
	return eventPayload{
		ToolName:   e.ToolName,
		WasBlocked: e.WasBlocked,
		RuleName:   e.RuleName,
		Layer:      e.Layer,
		Protocol:   e.Protocol,
		Direction:  e.Direction,
		Method:     e.Method,
		BlockType:  e.BlockType,
		APIType:    e.APIType.String(),
		Model:      e.Model,
		TraceID:    string(e.TraceID),
		SessionID:  string(e.SessionID),
		Arguments:  e.Arguments,
		Timestamp:  e.RecordedAt,
	}
}
