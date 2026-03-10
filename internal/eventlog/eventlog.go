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
	LayerProxyRequest  = "proxy_request"         // Request-side blocking (HTTP proxy)
	LayerProxyResponse = "proxy_response"        // Response-side blocking (HTTP proxy, non-streaming)
	LayerProxyStream   = "proxy_response_stream" // Response-side streaming (unbuffered, log-only)
	LayerProxyBuffer   = "proxy_response_buffer" // Response-side buffered streaming
	LayerStdioPipe     = "stdio_pipe"            // JSON-RPC stdio pipe inspection (ACP/MCP/autowrap)
	LayerMCPHTTP       = "mcp_http"              // MCP Streamable HTTP gateway
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
	Layer      string // LayerProxyRequest, LayerProxyResponse, LayerProxyStream, LayerProxyBuffer, LayerStdioPipe, LayerMCPHTTP
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
	ProxyRequestBlocks   atomic.Int64
	ProxyResponseBlocks  atomic.Int64
	ProxyResponseAllowed atomic.Int64

	// JSON-RPC stdio pipes
	StdioPipeBlocks  atomic.Int64
	StdioPipeAllowed atomic.Int64

	// MCP HTTP gateway
	MCPHTTPBlocks  atomic.Int64
	MCPHTTPAllowed atomic.Int64

	// Totals
	TotalToolCalls atomic.Int64
}

// GetStats returns a copy of current metrics.
func (m *Metrics) GetStats() map[string]int64 {
	return map[string]int64{
		"proxy_request_blocks":   m.ProxyRequestBlocks.Load(),
		"proxy_response_blocks":  m.ProxyResponseBlocks.Load(),
		"proxy_response_allowed": m.ProxyResponseAllowed.Load(),
		"stdio_pipe_blocks":      m.StdioPipeBlocks.Load(),
		"stdio_pipe_allowed":     m.StdioPipeAllowed.Load(),
		"mcp_http_blocks":        m.MCPHTTPBlocks.Load(),
		"mcp_http_allowed":       m.MCPHTTPAllowed.Load(),
		"total_tool_calls":       m.TotalToolCalls.Load(),
	}
}

// ProxyResponseBlockRate returns the percentage of calls blocked at the proxy response layer.
func (m *Metrics) ProxyResponseBlockRate() float64 {
	total := m.TotalToolCalls.Load()
	if total == 0 {
		return 0
	}
	return float64(m.ProxyResponseBlocks.Load()) / float64(total) * 100
}

// Reset clears all metrics (for testing).
func (m *Metrics) Reset() {
	m.ProxyRequestBlocks.Store(0)
	m.ProxyResponseBlocks.Store(0)
	m.ProxyResponseAllowed.Store(0)
	m.StdioPipeBlocks.Store(0)
	m.StdioPipeAllowed.Store(0)
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
		case LayerProxyRequest, LayerProxyResponse, LayerProxyStream, LayerProxyBuffer:
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
	case LayerProxyRequest:
		if event.WasBlocked {
			m.ProxyRequestBlocks.Add(1)
			m.TotalToolCalls.Add(1)
		}
	case LayerProxyResponse, LayerProxyStream, LayerProxyBuffer:
		if event.WasBlocked {
			m.ProxyResponseBlocks.Add(1)
		} else {
			m.ProxyResponseAllowed.Add(1)
		}
		m.TotalToolCalls.Add(1)
	case LayerStdioPipe:
		if event.WasBlocked {
			m.StdioPipeBlocks.Add(1)
		} else {
			m.StdioPipeAllowed.Add(1)
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
