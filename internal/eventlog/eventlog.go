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
	"errors"
	"sync"
	"sync/atomic"
	"time"

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
	LayerHook          = "hook"                  // PreToolUse hook evaluation (Claude Code, etc.)
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

	// RecordedAt is set by Record() to the time the event was recorded.
	// Used by SSE streaming to provide accurate event timestamps.
	RecordedAt time.Time
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

	// PreToolUse hooks (Claude Code, etc.)
	HookBlocks  atomic.Int64
	HookAllowed atomic.Int64

	// Totals
	TotalToolCalls atomic.Int64
}

// GetStats returns a copy of current metrics.
func (m *Metrics) GetStats() map[string]int64 {
	blocked := m.ProxyRequestBlocks.Load() + m.ProxyResponseBlocks.Load() +
		m.StdioPipeBlocks.Load() + m.MCPHTTPBlocks.Load() + m.HookBlocks.Load()
	allowed := m.ProxyResponseAllowed.Load() + m.StdioPipeAllowed.Load() +
		m.MCPHTTPAllowed.Load() + m.HookAllowed.Load()
	return map[string]int64{
		"proxy_request_blocks":   m.ProxyRequestBlocks.Load(),
		"proxy_response_blocks":  m.ProxyResponseBlocks.Load(),
		"proxy_response_allowed": m.ProxyResponseAllowed.Load(),
		"stdio_pipe_blocks":      m.StdioPipeBlocks.Load(),
		"stdio_pipe_allowed":     m.StdioPipeAllowed.Load(),
		"mcp_http_blocks":        m.MCPHTTPBlocks.Load(),
		"mcp_http_allowed":       m.MCPHTTPAllowed.Load(),
		"hook_blocks":            m.HookBlocks.Load(),
		"hook_allowed":           m.HookAllowed.Load(),
		"total_tool_calls":       m.TotalToolCalls.Load(),
		"blocked_tool_calls":     blocked,
		"allowed_tool_calls":     allowed,
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

// Seed adds a historical count to the appropriate per-layer counter.
// Used to restore metrics from persisted storage on startup.
func (m *Metrics) Seed(layer string, blocked bool, count int64) {
	switch layer {
	case LayerProxyRequest:
		if blocked {
			m.ProxyRequestBlocks.Add(count)
		}
	case LayerProxyResponse, LayerProxyStream, LayerProxyBuffer:
		if blocked {
			m.ProxyResponseBlocks.Add(count)
		} else {
			m.ProxyResponseAllowed.Add(count)
		}
	case LayerStdioPipe:
		if blocked {
			m.StdioPipeBlocks.Add(count)
		} else {
			m.StdioPipeAllowed.Add(count)
		}
	case LayerMCPHTTP:
		if blocked {
			m.MCPHTTPBlocks.Add(count)
		} else {
			m.MCPHTTPAllowed.Add(count)
		}
	case LayerHook:
		if blocked {
			m.HookBlocks.Add(count)
		} else {
			m.HookAllowed.Add(count)
		}
	}
	m.TotalToolCalls.Add(count)
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
	m.HookBlocks.Store(0)
	m.HookAllowed.Store(0)
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

// --- Live event subscriptions (for SSE streaming) ---

// MaxSubscribers limits concurrent event stream connections to prevent resource exhaustion.
const MaxSubscribers = 16

// ErrTooManySubscribers is returned when the subscriber limit is reached.
var ErrTooManySubscribers = errors.New("too many event subscribers")

var (
	subscribers sync.Map // map[uint64]chan Event
	nextSubID   atomic.Uint64
	subCount    atomic.Int32
)

// Subscribe registers a live event listener. Events are delivered on the returned
// channel with best-effort semantics: if the subscriber is slow, events are dropped
// (non-blocking send). Callers must call Unsubscribe when done.
//
// bufSize controls the channel buffer (clamped to minimum 1, recommended: 64).
// Returns ErrTooManySubscribers if MaxSubscribers is reached.
func Subscribe(bufSize int) (id uint64, ch <-chan Event, err error) {
	// Atomic CAS loop to prevent TOCTOU race on subscriber count.
	for {
		cur := subCount.Load()
		if cur >= int32(MaxSubscribers) {
			return 0, nil, ErrTooManySubscribers
		}
		if subCount.CompareAndSwap(cur, cur+1) {
			break
		}
	}
	if bufSize < 1 {
		bufSize = 1
	}
	c := make(chan Event, bufSize)
	id = nextSubID.Add(1)
	subscribers.Store(id, c)
	return id, c, nil
}

// Unsubscribe removes a subscriber. The channel is NOT closed to avoid
// send-on-closed-channel races with broadcast(). Callers should use context
// cancellation to signal the subscriber goroutine to stop reading.
func Unsubscribe(id uint64) {
	if _, ok := subscribers.LoadAndDelete(id); ok {
		subCount.Add(-1)
	}
}

// broadcast sends an event to all subscribers. Slow subscribers are skipped
// (non-blocking send) to prevent Record() from blocking.
func broadcast(event Event) {
	subscribers.Range(func(_, v any) bool {
		select {
		case v.(chan Event) <- event:
		default: // drop if subscriber is slow
		}
		return true
	})
}

// Record logs a security event to in-memory metrics and the configured sink.
// This is the single entry point for recording security events across all layers.
func Record(event Event) {
	event.RecordedAt = time.Now().UTC()

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
	case LayerHook:
		if event.WasBlocked {
			m.HookBlocks.Add(1)
		} else {
			m.HookAllowed.Add(1)
		}
		m.TotalToolCalls.Add(1)
	}

	// Persist to storage via sink.
	if s, ok := globalSink.Load().(Sink); ok && s != nil {
		s.LogEvent(event)
	}

	// Broadcast to live subscribers (SSE streams).
	broadcast(event)
}
