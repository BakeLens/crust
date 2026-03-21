package mcpgateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/BakeLens/crust/internal/eventlog"
	"github.com/BakeLens/crust/internal/jsonrpc"
	"github.com/BakeLens/crust/internal/rules"
)

// maxRequestBody is the maximum size of a POST request body (100MB).
const maxRequestBody = 100 * 1024 * 1024

// sessionHeader is the MCP session ID header.
const sessionHeader = "Mcp-Session-Id"

// sseMessageType is the SSE event type for JSON-RPC messages.
const sseMessageType = "message"

// HTTPGateway is an HTTP reverse proxy for MCP Streamable HTTP transport.
// It inspects JSON-RPC messages using the Crust rule engine and DLP scanner.
type HTTPGateway struct {
	upstream *url.URL
	engine   rules.RuleEvaluator
	client   *http.Client
	sessions *SessionStore
}

// NewHTTPGateway creates a new MCP HTTP gateway proxying to upstreamURL.
func NewHTTPGateway(upstreamURL string, engine rules.RuleEvaluator) (*HTTPGateway, error) {
	u, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("upstream URL must be http or https, got %q", u.Scheme)
	}
	return &HTTPGateway{
		upstream: u,
		engine:   engine,
		client: &http.Client{
			Timeout: 5 * time.Minute,
		},
		sessions: NewSessionStore(),
	}, nil
}

// Close releases resources held by the gateway (stops the session reaper goroutine).
func (g *HTTPGateway) Close() {
	g.sessions.Close()
}

// ServeHTTP dispatches to the appropriate handler based on HTTP method.
// Cross-origin browser requests are rejected before processing (CSRF protection).
func (g *HTTPGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := checkOrigin(r); err != nil {
		log.Warn("Blocked cross-origin request: %s", err)
		eventlog.Record(eventlog.Event{
			Layer:      eventlog.LayerMCPHTTP,
			WasBlocked: true,
			BlockType:  eventlog.BlockTypeSelfProtect,
		})
		http.Error(w, "Forbidden: "+err.Error(), http.StatusForbidden)
		return
	}

	// WebSocket upgrade — proxy at TCP level after origin validation.
	if isWebSocketUpgrade(r) {
		g.handleWebSocket(w, r)
		return
	}

	switch r.Method {
	case http.MethodPost:
		g.handlePost(w, r)
	case http.MethodGet:
		g.handleGet(w, r)
	case http.MethodDelete:
		g.handleDelete(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handlePost proxies a client→server JSON-RPC request.
func (g *HTTPGateway) handlePost(w http.ResponseWriter, r *http.Request) {
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBody))
	if err != nil {
		http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	var msg jsonrpc.Message
	if err := json.Unmarshal(body, &msg); err != nil {
		// Can't parse as JSON-RPC — reject to prevent inspection bypass
		http.Error(w, "Invalid JSON-RPC request", http.StatusBadRequest)
		return
	}

	// Inspect the request
	result := InspectRequest(g.engine, &msg)
	isBlocked := result.Decision == Block
	if result.ToolName != "" || isBlocked {
		eventlog.Record(eventlog.Event{
			Layer:      eventlog.LayerMCPHTTP,
			ToolName:   result.ToolName,
			Protocol:   "MCP",
			Direction:  "inbound",
			Method:     msg.Method,
			WasBlocked: isBlocked,
			RuleName:   result.RuleName,
		})
	}
	if isBlocked {
		log.Warn("Blocked MCP HTTP %s (tool=%s): %s", msg.Method, result.ToolName, result.RuleName)
		writeJSONRPCError(w, msg.ID, result.BlockMsg)
		return
	}
	if result.Decision == LogOnly {
		log.Info("Logged MCP HTTP %s (tool=%s): rule=%s", msg.Method, result.ToolName, result.RuleName)
	}

	// Forward to upstream
	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, g.upstream.String(), strings.NewReader(string(body)))
	if err != nil {
		http.Error(w, "Failed to create upstream request", http.StatusInternalServerError)
		return
	}
	upReq.Header.Set("Content-Type", "application/json")
	upReq.Header.Set("Accept", "application/json, text/event-stream")
	g.copyMCPHeaders(r, upReq)

	upResp, err := g.client.Do(upReq)
	if err != nil || upResp == nil {
		log.Warn("Upstream request failed: %v", err)
		http.Error(w, "Upstream request failed", http.StatusBadGateway)
		return
	}
	defer upResp.Body.Close()

	// Track session from upstream response
	if sid := upResp.Header.Get(sessionHeader); sid != "" {
		g.sessions.Track(sid)
	}

	respCT := upResp.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(respCT, "text/event-stream"):
		g.proxySSEResponse(w, r, upResp)
	case strings.HasPrefix(respCT, "application/json"):
		g.proxyJSONResponse(w, upResp, &msg)
	default:
		// Unknown content type — proxy transparently
		g.copyResponseHeaders(w, upResp)
		w.WriteHeader(upResp.StatusCode)
		_, _ = io.Copy(w, upResp.Body)
	}
}

// handleGet proxies a server-initiated SSE notification stream.
func (g *HTTPGateway) handleGet(w http.ResponseWriter, r *http.Request) {
	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, g.upstream.String(), nil)
	if err != nil {
		http.Error(w, "Failed to create upstream request", http.StatusInternalServerError)
		return
	}
	upReq.Header.Set("Accept", "text/event-stream")
	g.copyMCPHeaders(r, upReq)

	upResp, err := g.client.Do(upReq)
	if err != nil || upResp == nil {
		log.Warn("Upstream request failed: %v", err)
		http.Error(w, "Upstream request failed", http.StatusBadGateway)
		return
	}
	defer upResp.Body.Close()

	if upResp.StatusCode != http.StatusOK {
		g.copyResponseHeaders(w, upResp)
		w.WriteHeader(upResp.StatusCode)
		_, _ = io.Copy(w, upResp.Body)
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	if sid := upResp.Header.Get(sessionHeader); sid != "" {
		w.Header().Set(sessionHeader, sid)
		g.sessions.Track(sid)
	}
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	ctx := r.Context()
	ProxySSEStream(ctx, upResp.Body, w, func(event SSEEvent) (SSEEvent, bool) {
		if event.Type != sseMessageType && event.Type != "" {
			return event, true // non-message events pass through
		}

		var msg jsonrpc.Message
		if err := json.Unmarshal([]byte(event.Data), &msg); err != nil {
			return event, true // not JSON-RPC, pass through
		}

		// Server→client: requests get InspectRequest, responses get InspectResponse
		var result InspectResult
		if msg.Method != "" {
			result = InspectRequest(g.engine, &msg)
		} else {
			result = InspectResponse(g.engine, &msg)
		}

		isBlocked := result.Decision == Block
		if result.ToolName != "" || isBlocked {
			eventlog.Record(eventlog.Event{
				Layer:      eventlog.LayerMCPHTTP,
				ToolName:   result.ToolName,
				Protocol:   "MCP",
				Direction:  "outbound",
				Method:     msg.Method,
				WasBlocked: isBlocked,
				RuleName:   result.RuleName,
			})
		}
		if isBlocked {
			log.Warn("Blocked MCP HTTP SSE event (rule=%s)", result.RuleName)
			return event, false // drop blocked event
		}
		return event, true
	})
}

// handleDelete proxies a session termination request.
func (g *HTTPGateway) handleDelete(w http.ResponseWriter, r *http.Request) {
	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodDelete, g.upstream.String(), nil)
	if err != nil {
		http.Error(w, "Failed to create upstream request", http.StatusInternalServerError)
		return
	}
	g.copyMCPHeaders(r, upReq)

	upResp, err := g.client.Do(upReq)
	if err != nil || upResp == nil {
		log.Warn("Upstream request failed: %v", err)
		http.Error(w, "Upstream request failed", http.StatusBadGateway)
		return
	}
	defer upResp.Body.Close()

	// Clean up session
	if sid := r.Header.Get(sessionHeader); sid != "" {
		g.sessions.Remove(sid)
	}

	g.copyResponseHeaders(w, upResp)
	w.WriteHeader(upResp.StatusCode)
	_, _ = io.Copy(w, upResp.Body)
}

// proxyJSONResponse inspects and forwards a JSON response.
func (g *HTTPGateway) proxyJSONResponse(w http.ResponseWriter, upResp *http.Response, reqMsg *jsonrpc.Message) {
	respBody, err := io.ReadAll(upResp.Body)
	if err != nil {
		http.Error(w, "Failed to read upstream response", http.StatusBadGateway)
		return
	}

	var respMsg jsonrpc.Message
	if err := json.Unmarshal(respBody, &respMsg); err != nil {
		// Not valid JSON-RPC — forward as-is
		g.copyResponseHeaders(w, upResp)
		w.WriteHeader(upResp.StatusCode)
		writeBody(w, respBody)
		return
	}

	result := InspectResponse(g.engine, &respMsg)
	if result.Decision == Block {
		eventlog.Record(eventlog.Event{
			Layer:      eventlog.LayerMCPHTTP,
			Protocol:   "MCP",
			Direction:  "outbound",
			WasBlocked: true,
			RuleName:   result.RuleName,
			BlockType:  eventlog.BlockTypeDLP,
		})
		log.Warn("Blocked MCP HTTP response (DLP): rule=%s", result.RuleName)
		writeJSONRPCError(w, reqMsg.ID, result.BlockMsg)
		return
	}

	// Forward the original response
	g.copyResponseHeaders(w, upResp)
	w.WriteHeader(upResp.StatusCode)
	writeBody(w, respBody)
}

// proxySSEResponse streams an SSE response with per-event inspection.
func (g *HTTPGateway) proxySSEResponse(w http.ResponseWriter, r *http.Request, upResp *http.Response) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	if sid := upResp.Header.Get(sessionHeader); sid != "" {
		w.Header().Set(sessionHeader, sid)
	}
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	ctx := r.Context()
	ProxySSEStream(ctx, upResp.Body, w, func(event SSEEvent) (SSEEvent, bool) {
		if event.Type != sseMessageType && event.Type != "" {
			return event, true
		}

		var msg jsonrpc.Message
		if err := json.Unmarshal([]byte(event.Data), &msg); err != nil {
			return event, true
		}

		result := InspectResponse(g.engine, &msg)
		if result.Decision == Block {
			eventlog.Record(eventlog.Event{
				Layer:      eventlog.LayerMCPHTTP,
				Protocol:   "MCP",
				Direction:  "outbound",
				WasBlocked: true,
				RuleName:   result.RuleName,
				BlockType:  eventlog.BlockTypeDLP,
			})
			log.Warn("Blocked MCP HTTP SSE response (DLP): rule=%s", result.RuleName)
			return event, false
		}
		return event, true
	})
}

// copyMCPHeaders copies MCP-relevant headers from client request to upstream request.
func (g *HTTPGateway) copyMCPHeaders(from *http.Request, to *http.Request) {
	if sid := from.Header.Get(sessionHeader); sid != "" {
		to.Header.Set(sessionHeader, sid)
	}
	if lastID := from.Header.Get("Last-Event-ID"); lastID != "" {
		to.Header.Set("Last-Event-ID", lastID)
	}
}

// copyResponseHeaders copies response headers from upstream to client.
func (g *HTTPGateway) copyResponseHeaders(w http.ResponseWriter, upResp *http.Response) {
	for k, vv := range upResp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
}

// writeJSONRPCError writes a JSON-RPC error response with code -32001.
func writeJSONRPCError(w http.ResponseWriter, id json.RawMessage, msg string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	resp := jsonrpc.ErrorResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   jsonrpc.ErrorObj{Code: jsonrpc.BlockedError, Message: msg},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	//nolint:errcheck // best-effort write to HTTP client
	json.NewEncoder(w).Encode(resp)
}

// writeBody writes the response body after headers are sent.
// Accepts io.Writer to decouple from http.ResponseWriter.
// Error is intentionally discarded: headers are already sent,
// and the only failure mode is a broken connection.
func writeBody(w io.Writer, data []byte) {
	if _, err := w.Write(data); err != nil {
		return
	}
}
