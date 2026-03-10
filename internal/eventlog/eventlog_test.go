package eventlog

import (
	"sync"
	"testing"
)

// mockSink records events for verification.
type mockSink struct {
	mu     sync.Mutex
	events []Event
}

func (m *mockSink) LogEvent(event Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
}

func (m *mockSink) last() Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.events[len(m.events)-1]
}

func resetAll() {
	GetMetrics().Reset()
	globalSink = globalSinkZero // clear sink
}

// globalSinkZero is the zero value used to clear the atomic.Value.
var globalSinkZero = globalSink

func TestRecord_LayerMetrics(t *testing.T) {
	tests := []struct {
		name  string
		event Event
		check func(t *testing.T, m *Metrics)
	}{
		{
			name:  "L0 blocked increments ProxyRequestBlocks and TotalToolCalls",
			event: Event{Layer: LayerProxyRequest, WasBlocked: true, ToolName: "test"},
			check: func(t *testing.T, m *Metrics) {
				if m.ProxyRequestBlocks.Load() != 1 {
					t.Errorf("ProxyRequestBlocks = %d, want 1", m.ProxyRequestBlocks.Load())
				}
				if m.TotalToolCalls.Load() != 1 {
					t.Errorf("TotalToolCalls = %d, want 1", m.TotalToolCalls.Load())
				}
			},
		},
		{
			name:  "L0 not blocked increments nothing",
			event: Event{Layer: LayerProxyRequest, WasBlocked: false, ToolName: "test"},
			check: func(t *testing.T, m *Metrics) {
				if m.ProxyRequestBlocks.Load() != 0 {
					t.Errorf("ProxyRequestBlocks = %d, want 0", m.ProxyRequestBlocks.Load())
				}
				if m.TotalToolCalls.Load() != 0 {
					t.Errorf("TotalToolCalls = %d, want 0", m.TotalToolCalls.Load())
				}
			},
		},
		{
			name:  "L1 blocked increments ProxyResponseBlocks and TotalToolCalls",
			event: Event{Layer: LayerProxyResponse, WasBlocked: true, ToolName: "test"},
			check: func(t *testing.T, m *Metrics) {
				if m.ProxyResponseBlocks.Load() != 1 {
					t.Errorf("ProxyResponseBlocks = %d, want 1", m.ProxyResponseBlocks.Load())
				}
				if m.TotalToolCalls.Load() != 1 {
					t.Errorf("TotalToolCalls = %d, want 1", m.TotalToolCalls.Load())
				}
			},
		},
		{
			name:  "L1 allowed increments ProxyResponseAllowed and TotalToolCalls",
			event: Event{Layer: LayerProxyResponse, WasBlocked: false, ToolName: "test"},
			check: func(t *testing.T, m *Metrics) {
				if m.ProxyResponseAllowed.Load() != 1 {
					t.Errorf("ProxyResponseAllowed = %d, want 1", m.ProxyResponseAllowed.Load())
				}
				if m.TotalToolCalls.Load() != 1 {
					t.Errorf("TotalToolCalls = %d, want 1", m.TotalToolCalls.Load())
				}
			},
		},
		{
			name:  "L1_stream blocked increments ProxyResponseBlocks",
			event: Event{Layer: LayerProxyStream, WasBlocked: true, ToolName: "test"},
			check: func(t *testing.T, m *Metrics) {
				if m.ProxyResponseBlocks.Load() != 1 {
					t.Errorf("ProxyResponseBlocks = %d, want 1", m.ProxyResponseBlocks.Load())
				}
				if m.TotalToolCalls.Load() != 1 {
					t.Errorf("TotalToolCalls = %d, want 1", m.TotalToolCalls.Load())
				}
			},
		},
		{
			name:  "L1_buffer allowed increments ProxyResponseAllowed",
			event: Event{Layer: LayerProxyBuffer, WasBlocked: false, ToolName: "test"},
			check: func(t *testing.T, m *Metrics) {
				if m.ProxyResponseAllowed.Load() != 1 {
					t.Errorf("ProxyResponseAllowed = %d, want 1", m.ProxyResponseAllowed.Load())
				}
				if m.TotalToolCalls.Load() != 1 {
					t.Errorf("TotalToolCalls = %d, want 1", m.TotalToolCalls.Load())
				}
			},
		},
		{
			name:  "pipe blocked increments StdioPipeBlocks",
			event: Event{Layer: LayerStdioPipe, WasBlocked: true, ToolName: "test"},
			check: func(t *testing.T, m *Metrics) {
				if m.StdioPipeBlocks.Load() != 1 {
					t.Errorf("StdioPipeBlocks = %d, want 1", m.StdioPipeBlocks.Load())
				}
				if m.TotalToolCalls.Load() != 1 {
					t.Errorf("TotalToolCalls = %d, want 1", m.TotalToolCalls.Load())
				}
			},
		},
		{
			name:  "pipe allowed increments StdioPipeAllowed",
			event: Event{Layer: LayerStdioPipe, WasBlocked: false, ToolName: "test"},
			check: func(t *testing.T, m *Metrics) {
				if m.StdioPipeAllowed.Load() != 1 {
					t.Errorf("StdioPipeAllowed = %d, want 1", m.StdioPipeAllowed.Load())
				}
				if m.TotalToolCalls.Load() != 1 {
					t.Errorf("TotalToolCalls = %d, want 1", m.TotalToolCalls.Load())
				}
			},
		},
		{
			name:  "mcp_http blocked increments MCPHTTPBlocks",
			event: Event{Layer: LayerMCPHTTP, WasBlocked: true, ToolName: "test"},
			check: func(t *testing.T, m *Metrics) {
				if m.MCPHTTPBlocks.Load() != 1 {
					t.Errorf("MCPHTTPBlocks = %d, want 1", m.MCPHTTPBlocks.Load())
				}
				if m.TotalToolCalls.Load() != 1 {
					t.Errorf("TotalToolCalls = %d, want 1", m.TotalToolCalls.Load())
				}
			},
		},
		{
			name:  "mcp_http allowed increments MCPHTTPAllowed",
			event: Event{Layer: LayerMCPHTTP, WasBlocked: false, ToolName: "test"},
			check: func(t *testing.T, m *Metrics) {
				if m.MCPHTTPAllowed.Load() != 1 {
					t.Errorf("MCPHTTPAllowed = %d, want 1", m.MCPHTTPAllowed.Load())
				}
				if m.TotalToolCalls.Load() != 1 {
					t.Errorf("TotalToolCalls = %d, want 1", m.TotalToolCalls.Load())
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetAll()
			Record(tc.event)
			tc.check(t, GetMetrics())
		})
	}
}

func TestRecord_InferProtocol(t *testing.T) {
	httpLayers := []string{LayerProxyRequest, LayerProxyResponse, LayerProxyStream, LayerProxyBuffer}
	for _, layer := range httpLayers {
		t.Run(layer+"_defaults_to_HTTP", func(t *testing.T) {
			resetAll()
			sink := &mockSink{}
			SetSink(sink)
			Record(Event{Layer: layer, ToolName: "test"})
			got := sink.last().Protocol
			if got != "HTTP" {
				t.Errorf("Protocol = %q, want %q", got, "HTTP")
			}
		})
	}

	nonHTTPLayers := []string{LayerStdioPipe, LayerMCPHTTP}
	for _, layer := range nonHTTPLayers {
		t.Run(layer+"_stays_empty", func(t *testing.T) {
			resetAll()
			sink := &mockSink{}
			SetSink(sink)
			Record(Event{Layer: layer, ToolName: "test"})
			got := sink.last().Protocol
			if got != "" {
				t.Errorf("Protocol = %q, want empty", got)
			}
		})
	}

	t.Run("explicit_protocol_preserved", func(t *testing.T) {
		resetAll()
		sink := &mockSink{}
		SetSink(sink)
		Record(Event{Layer: LayerProxyRequest, Protocol: "ACP", ToolName: "test"})
		got := sink.last().Protocol
		if got != "ACP" {
			t.Errorf("Protocol = %q, want %q", got, "ACP")
		}
	})
}

func TestRecord_InferBlockType(t *testing.T) {
	tests := []struct {
		name      string
		event     Event
		wantBlock string
	}{
		{
			name:      "selfprotect rule",
			event:     Event{Layer: LayerProxyRequest, WasBlocked: true, RuleName: "builtin:protect-crust-socket"},
			wantBlock: BlockTypeSelfProtect,
		},
		{
			name:      "regular rule",
			event:     Event{Layer: LayerProxyRequest, WasBlocked: true, RuleName: "user:deny-rm"},
			wantBlock: BlockTypeRule,
		},
		{
			name:      "not blocked has empty BlockType",
			event:     Event{Layer: LayerProxyRequest, WasBlocked: false, RuleName: ""},
			wantBlock: "",
		},
		{
			name:      "blocked but no rule name has empty BlockType",
			event:     Event{Layer: LayerProxyRequest, WasBlocked: true, RuleName: ""},
			wantBlock: "",
		},
		{
			name:      "explicit BlockType preserved",
			event:     Event{Layer: LayerProxyRequest, WasBlocked: true, RuleName: "x", BlockType: BlockTypeDLP},
			wantBlock: BlockTypeDLP,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetAll()
			sink := &mockSink{}
			SetSink(sink)
			Record(tc.event)
			got := sink.last().BlockType
			if got != tc.wantBlock {
				t.Errorf("BlockType = %q, want %q", got, tc.wantBlock)
			}
		})
	}
}

func TestRecord_SinkCalled(t *testing.T) {
	resetAll()
	sink := &mockSink{}
	SetSink(sink)

	ev := Event{
		Layer:      LayerProxyResponse,
		ToolName:   "bash",
		WasBlocked: true,
		RuleName:   "user:deny-rm",
	}
	Record(ev)

	if len(sink.events) != 1 {
		t.Fatalf("sink received %d events, want 1", len(sink.events))
	}
	got := sink.events[0]
	if got.ToolName != "bash" {
		t.Errorf("ToolName = %q, want %q", got.ToolName, "bash")
	}
	if got.Layer != LayerProxyResponse {
		t.Errorf("Layer = %q, want %q", got.Layer, LayerProxyResponse)
	}
	if !got.WasBlocked {
		t.Error("WasBlocked = false, want true")
	}
	if got.Protocol != "HTTP" {
		t.Errorf("Protocol = %q, want %q (inferred)", got.Protocol, "HTTP")
	}
	if got.BlockType != BlockTypeRule {
		t.Errorf("BlockType = %q, want %q (inferred)", got.BlockType, BlockTypeRule)
	}
}

func TestRecord_NoSinkNoPanic(t *testing.T) {
	resetAll()
	// No sink set — should not panic.
	Record(Event{Layer: LayerProxyRequest, WasBlocked: true, ToolName: "test"})
}

func TestMetrics_GetStats(t *testing.T) {
	resetAll()
	m := GetMetrics()
	m.ProxyRequestBlocks.Store(1)
	m.ProxyResponseBlocks.Store(2)
	m.ProxyResponseAllowed.Store(3)
	m.StdioPipeBlocks.Store(4)
	m.StdioPipeAllowed.Store(5)
	m.MCPHTTPBlocks.Store(6)
	m.MCPHTTPAllowed.Store(7)
	m.TotalToolCalls.Store(8)

	stats := m.GetStats()

	expected := map[string]int64{
		"proxy_request_blocks":   1,
		"proxy_response_blocks":  2,
		"proxy_response_allowed": 3,
		"stdio_pipe_blocks":      4,
		"stdio_pipe_allowed":     5,
		"mcp_http_blocks":        6,
		"mcp_http_allowed":       7,
		"total_tool_calls":       8,
	}

	if len(stats) != len(expected) {
		t.Fatalf("GetStats returned %d keys, want %d", len(stats), len(expected))
	}

	for k, want := range expected {
		got, ok := stats[k]
		if !ok {
			t.Errorf("missing key %q", k)
			continue
		}
		if got != want {
			t.Errorf("stats[%q] = %d, want %d", k, got, want)
		}
	}
}

func TestMetrics_Reset(t *testing.T) {
	m := GetMetrics()
	m.ProxyRequestBlocks.Store(10)
	m.ProxyResponseBlocks.Store(20)
	m.ProxyResponseAllowed.Store(30)
	m.StdioPipeBlocks.Store(40)
	m.StdioPipeAllowed.Store(50)
	m.MCPHTTPBlocks.Store(60)
	m.MCPHTTPAllowed.Store(70)
	m.TotalToolCalls.Store(80)

	m.Reset()

	stats := m.GetStats()
	for k, v := range stats {
		if v != 0 {
			t.Errorf("after Reset, stats[%q] = %d, want 0", k, v)
		}
	}
}

func TestMetrics_ProxyResponseBlockRate(t *testing.T) {
	tests := []struct {
		name       string
		l1blocks   int64
		totalCalls int64
		want       float64
	}{
		{"zero total returns 0", 0, 0, 0},
		{"no blocks returns 0", 0, 10, 0},
		{"50 percent", 5, 10, 50.0},
		{"100 percent", 10, 10, 100.0},
		{"33.33 percent", 1, 3, 100.0 / 3.0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := GetMetrics()
			m.Reset()
			m.ProxyResponseBlocks.Store(tc.l1blocks)
			m.TotalToolCalls.Store(tc.totalCalls)

			got := m.ProxyResponseBlockRate()
			diff := got - tc.want
			if diff < -0.01 || diff > 0.01 {
				t.Errorf("ProxyResponseBlockRate() = %f, want %f", got, tc.want)
			}
		})
	}
}
