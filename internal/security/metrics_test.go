package security

import (
	"encoding/json"
	"testing"

	"github.com/BakeLens/crust/internal/eventlog"
)

func TestMetricsCountAccuracy(t *testing.T) {
	eventlog.GetMetrics().Reset()

	// 3 proxy request blocked events
	for range 3 {
		eventlog.Record(eventlog.Event{
			Layer:      eventlog.LayerProxyRequest,
			ToolName:   "Read",
			Arguments:  json.RawMessage(`{"path":"/etc/shadow"}`),
			WasBlocked: true,
			RuleName:   "test-rule",
		})
	}

	// 2 proxy response blocked events (one non-streaming, one buffered)
	eventlog.Record(eventlog.Event{
		Layer:      eventlog.LayerProxyResponse,
		ToolName:   "Bash",
		Arguments:  json.RawMessage(`{"command":"rm -rf /"}`),
		WasBlocked: true,
		RuleName:   "test-rule",
	})
	eventlog.Record(eventlog.Event{
		Layer:      eventlog.LayerProxyBuffer,
		ToolName:   "Write",
		Arguments:  json.RawMessage(`{"path":"/etc/passwd"}`),
		WasBlocked: true,
		RuleName:   "test-rule",
	})

	// 1 proxy response allowed event
	eventlog.Record(eventlog.Event{
		Layer:      eventlog.LayerProxyResponse,
		ToolName:   "Read",
		Arguments:  json.RawMessage(`{"path":"README.md"}`),
		WasBlocked: false,
	})

	m := eventlog.GetMetrics()

	if got := m.ProxyRequestBlocks.Load(); got != 3 {
		t.Errorf("ProxyRequestBlocks = %d, want 3", got)
	}
	if got := m.ProxyResponseBlocks.Load(); got != 2 {
		t.Errorf("ProxyResponseBlocks = %d, want 2", got)
	}
	if got := m.ProxyResponseAllowed.Load(); got != 1 {
		t.Errorf("ProxyResponseAllowed = %d, want 1", got)
	}
	if got := m.TotalToolCalls.Load(); got != 6 {
		t.Errorf("TotalToolCalls = %d, want 6", got)
	}
}

func TestMetricsReset(t *testing.T) {
	m := eventlog.GetMetrics()

	// Populate counters
	m.ProxyRequestBlocks.Add(5)
	m.ProxyResponseBlocks.Add(3)
	m.ProxyResponseAllowed.Add(7)
	m.TotalToolCalls.Add(15)

	m.Reset()

	if got := m.ProxyRequestBlocks.Load(); got != 0 {
		t.Errorf("ProxyRequestBlocks after reset = %d, want 0", got)
	}
	if got := m.ProxyResponseBlocks.Load(); got != 0 {
		t.Errorf("ProxyResponseBlocks after reset = %d, want 0", got)
	}
	if got := m.ProxyResponseAllowed.Load(); got != 0 {
		t.Errorf("ProxyResponseAllowed after reset = %d, want 0", got)
	}
	if got := m.TotalToolCalls.Load(); got != 0 {
		t.Errorf("TotalToolCalls after reset = %d, want 0", got)
	}
}

func TestBlockedTotal(t *testing.T) {
	eventlog.GetMetrics().Reset()

	// Record events at different layers
	eventlog.Record(eventlog.Event{Layer: eventlog.LayerProxyRequest, ToolName: "Read", WasBlocked: true, RuleName: "r1"})
	eventlog.Record(eventlog.Event{Layer: eventlog.LayerProxyResponse, ToolName: "Bash", WasBlocked: true, RuleName: "r2"})
	eventlog.Record(eventlog.Event{Layer: eventlog.LayerProxyStream, ToolName: "Write", WasBlocked: true, RuleName: "r3"})
	eventlog.Record(eventlog.Event{Layer: eventlog.LayerProxyBuffer, ToolName: "Edit", WasBlocked: true, RuleName: "r4"})
	eventlog.Record(eventlog.Event{Layer: eventlog.LayerProxyResponse, ToolName: "Read", WasBlocked: false})

	m := eventlog.GetMetrics()
	blocked := m.ProxyRequestBlocks.Load() + m.ProxyResponseBlocks.Load()

	if blocked != 4 {
		t.Errorf("total blocked = %d, want 4", blocked)
	}
	if got := m.TotalToolCalls.Load(); got != 5 {
		t.Errorf("TotalToolCalls = %d, want 5", got)
	}

	// Verify invariant: total = blocked + allowed
	allowed := m.ProxyResponseAllowed.Load()
	if blocked+allowed != m.TotalToolCalls.Load() {
		t.Errorf("invariant broken: blocked(%d) + allowed(%d) != total(%d)", blocked, allowed, m.TotalToolCalls.Load())
	}
}

func TestGetStatsMap(t *testing.T) {
	eventlog.GetMetrics().Reset()

	eventlog.Record(eventlog.Event{Layer: eventlog.LayerProxyRequest, ToolName: "Read", WasBlocked: true, RuleName: "r1"})
	eventlog.Record(eventlog.Event{Layer: eventlog.LayerProxyResponse, ToolName: "Bash", WasBlocked: true, RuleName: "r2"})
	eventlog.Record(eventlog.Event{Layer: eventlog.LayerProxyResponse, ToolName: "Read", WasBlocked: false})

	stats := eventlog.GetMetrics().GetStats()

	if stats["total_tool_calls"] != 3 {
		t.Errorf("total_tool_calls = %d, want 3", stats["total_tool_calls"])
	}
	if stats["proxy_request_blocks"] != 1 {
		t.Errorf("layer0_blocks = %d, want 1", stats["proxy_request_blocks"])
	}
	if stats["proxy_response_blocks"] != 1 {
		t.Errorf("layer1_blocks = %d, want 1", stats["proxy_response_blocks"])
	}
	if stats["proxy_response_allowed"] != 1 {
		t.Errorf("layer1_allowed = %d, want 1", stats["proxy_response_allowed"])
	}
}

func TestLayer0NonBlockedDroppedFromMetrics(t *testing.T) {
	eventlog.GetMetrics().Reset()

	// Non-blocked proxy request events shouldn't happen in practice.
	// They are silently dropped to preserve the invariant:
	//   TotalToolCalls == ProxyRequestBlocks + ProxyResponseBlocks + ProxyResponseAllowed
	eventlog.Record(eventlog.Event{Layer: eventlog.LayerProxyRequest, ToolName: "Read", WasBlocked: false})

	m := eventlog.GetMetrics()
	if got := m.ProxyRequestBlocks.Load(); got != 0 {
		t.Errorf("ProxyRequestBlocks = %d, want 0", got)
	}
	if got := m.TotalToolCalls.Load(); got != 0 {
		t.Errorf("TotalToolCalls = %d, want 0 (non-blocked proxy request dropped)", got)
	}
}

func TestInvariantTotalEqualsSubcounters(t *testing.T) {
	eventlog.GetMetrics().Reset()

	// Mix of all layer types
	eventlog.Record(eventlog.Event{Layer: eventlog.LayerProxyRequest, ToolName: "Read", WasBlocked: true, RuleName: "r1"})
	eventlog.Record(eventlog.Event{Layer: eventlog.LayerProxyRequest, ToolName: "Write", WasBlocked: true, RuleName: "r2"})
	eventlog.Record(eventlog.Event{Layer: eventlog.LayerProxyResponse, ToolName: "Bash", WasBlocked: true, RuleName: "r3"})
	eventlog.Record(eventlog.Event{Layer: eventlog.LayerProxyResponse, ToolName: "Read", WasBlocked: false})
	eventlog.Record(eventlog.Event{Layer: eventlog.LayerProxyStream, ToolName: "Write", WasBlocked: true, RuleName: "r4"})
	eventlog.Record(eventlog.Event{Layer: eventlog.LayerProxyStream, ToolName: "Edit", WasBlocked: false})
	eventlog.Record(eventlog.Event{Layer: eventlog.LayerProxyBuffer, ToolName: "Bash", WasBlocked: true, RuleName: "r5"})
	// Non-blocked proxy request should be silently dropped:
	eventlog.Record(eventlog.Event{Layer: eventlog.LayerProxyRequest, ToolName: "Read", WasBlocked: false})

	m := eventlog.GetMetrics()
	sum := m.ProxyRequestBlocks.Load() + m.ProxyResponseBlocks.Load() + m.ProxyResponseAllowed.Load()

	if m.TotalToolCalls.Load() != sum {
		t.Errorf("invariant broken: TotalToolCalls(%d) != L0(%d)+L1B(%d)+L1A(%d) = %d",
			m.TotalToolCalls.Load(), m.ProxyRequestBlocks.Load(), m.ProxyResponseBlocks.Load(),
			m.ProxyResponseAllowed.Load(), sum)
	}
	if m.TotalToolCalls.Load() != 7 {
		t.Errorf("TotalToolCalls = %d, want 7 (1 non-blocked proxy request dropped)", m.TotalToolCalls.Load())
	}
}
