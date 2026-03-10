// Package eventlog provides unified security event recording across all
// crust transport layers (HTTP proxy, JSON-RPC stdio pipes, MCP HTTP gateway).
//
// Architecture:
//
//	httpproxy ──┐
//	jsonrpc  ───┤──▶ eventlog.Record(Event{...})
//	mcpgateway ─┤        │
//	security ───┘        ├─▶ in-memory Metrics (atomic counters)
//	                     └─▶ Sink.LogEvent() → telemetry DB (if registered)
//
// The Sink interface breaks the import cycle: transport packages import
// eventlog (lightweight), while security implements the Sink to persist
// events to SQLite via the telemetry package. security.Manager calls
// SetSink() once during startup.
//
// To record events from a new call site, call Record() with an Event
// populated with the appropriate Layer constant and transport metadata.
package eventlog

import (
	"encoding/json"
	"sync/atomic"

	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/types"
)

var log = logger.New("eventlog")

// Layer constants for telemetry tracking.
const (
	LayerL0       = "L0"        // Request-side blocking (HTTP proxy Layer 0)
	LayerL1       = "L1"        // Response-side blocking (HTTP proxy Layer 1, non-streaming)
	LayerL1Stream = "L1_stream" // Response-side streaming (unbuffered, log-only)
	LayerL1Buffer = "L1_buffer" // Response-side buffered streaming
	LayerPipe     = "pipe"      // JSON-RPC stdio pipe inspection (ACP/MCP/autowrap)
	LayerMCPHTTP  = "mcp_http"  // MCP Streamable HTTP gateway
)

// BlockType constants describe what caused a block.
const (
	BlockTypeRule        = "rule"
	BlockTypeDLP         = "dlp"
	BlockTypeSelfProtect = "selfprotect"
	BlockTypeMalformed   = "malformed"
)

// Event represents a tool call evaluation event at any layer.
type Event struct {
	Layer      string // LayerL0, LayerL1, LayerL1Stream, LayerL1Buffer, LayerPipe, LayerMCPHTTP
	TraceID    types.TraceID
	SessionID  types.SessionID
	ToolName   string
	Arguments  json.RawMessage
	APIType    types.APIType
	Model      string
	WasBlocked bool
	RuleName   string

	// Transport metadata (zero-value defaults preserve backward compatibility).
	Protocol  string // "HTTP", "ACP", "MCP", "Stdio"
	Direction string // "inbound" (client→server), "outbound" (server→client)
	Method    string // JSON-RPC method name (e.g., "tools/call")
	BlockType string // BlockTypeRule, BlockTypeDLP, BlockTypeSelfProtect, BlockTypeMalformed
}

// Metrics tracks blocking statistics for all layers.
type Metrics struct {
	// HTTP proxy
	Layer0Blocks  atomic.Int64
	Layer1Blocks  atomic.Int64
	Layer1Allowed atomic.Int64

	// JSON-RPC stdio pipes
	PipeBlocks  atomic.Int64
	PipeAllowed atomic.Int64

	// MCP HTTP gateway
	MCPHTTPBlocks  atomic.Int64
	MCPHTTPAllowed atomic.Int64

	// Totals
	TotalToolCalls atomic.Int64
}

// GetStats returns a copy of current metrics.
func (m *Metrics) GetStats() map[string]int64 {
	return map[string]int64{
		"layer0_blocks":    m.Layer0Blocks.Load(),
		"layer1_blocks":    m.Layer1Blocks.Load(),
		"layer1_allowed":   m.Layer1Allowed.Load(),
		"pipe_blocks":      m.PipeBlocks.Load(),
		"pipe_allowed":     m.PipeAllowed.Load(),
		"mcp_http_blocks":  m.MCPHTTPBlocks.Load(),
		"mcp_http_allowed": m.MCPHTTPAllowed.Load(),
		"total_tool_calls": m.TotalToolCalls.Load(),
	}
}

// Layer1BlockRate returns the percentage of calls blocked at Layer 1.
func (m *Metrics) Layer1BlockRate() float64 {
	total := m.TotalToolCalls.Load()
	if total == 0 {
		return 0
	}
	return float64(m.Layer1Blocks.Load()) / float64(total) * 100
}

// Reset clears all metrics (for testing).
func (m *Metrics) Reset() {
	m.Layer0Blocks.Store(0)
	m.Layer1Blocks.Store(0)
	m.Layer1Allowed.Store(0)
	m.PipeBlocks.Store(0)
	m.PipeAllowed.Store(0)
	m.MCPHTTPBlocks.Store(0)
	m.MCPHTTPAllowed.Store(0)
	m.TotalToolCalls.Store(0)
}

var globalMetrics = &Metrics{}

// GetMetrics returns the global metrics.
func GetMetrics() *Metrics { return globalMetrics }

// Sink is the interface for persisting events to storage.
// Implemented by the security package to break the import cycle.
type Sink interface {
	LogEvent(event Event)
}

var globalSink atomic.Value // stores Sink

// SetSink sets the global event sink (called once during init by security.Manager).
func SetSink(s Sink) { globalSink.Store(s) }

// Record logs a security event to in-memory metrics and the configured sink.
// This is the single entry point for recording security events across all layers.
func Record(event Event) {
	// Infer defaults for backward compatibility.
	if event.Protocol == "" {
		switch event.Layer {
		case LayerL0, LayerL1, LayerL1Stream, LayerL1Buffer:
			event.Protocol = "HTTP"
		}
	}
	if event.BlockType == "" && event.WasBlocked && event.RuleName != "" {
		if len(event.RuleName) > 22 && event.RuleName[:22] == "builtin:protect-crust-" {
			event.BlockType = BlockTypeSelfProtect
		} else {
			event.BlockType = BlockTypeRule
		}
	}

	log.Debug("Record: layer=%s proto=%s tool=%s blocked=%v rule=%s",
		event.Layer, event.Protocol, event.ToolName, event.WasBlocked, event.RuleName)

	m := globalMetrics

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
	case LayerPipe:
		if event.WasBlocked {
			m.PipeBlocks.Add(1)
		} else {
			m.PipeAllowed.Add(1)
		}
		m.TotalToolCalls.Add(1)
	case LayerMCPHTTP:
		if event.WasBlocked {
			m.MCPHTTPBlocks.Add(1)
		} else {
			m.MCPHTTPAllowed.Add(1)
		}
		m.TotalToolCalls.Add(1)
	}

	// Persist to storage via sink.
	if s, ok := globalSink.Load().(Sink); ok && s != nil {
		s.LogEvent(event)
	}
}
