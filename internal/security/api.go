//go:build !libcrust

package security

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/BakeLens/crust/internal/agentdetect"
	"github.com/BakeLens/crust/internal/api"
	"github.com/BakeLens/crust/internal/eventlog"
	"github.com/BakeLens/crust/internal/mcpgateway"
	"github.com/BakeLens/crust/internal/monitor"
	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/telemetry"
)

// APIServer handles HTTP API requests for security management and telemetry.
type APIServer struct {
	storage      *telemetry.Storage
	interceptor  *Interceptor
	engine       rules.RuleEvaluator
	manager      *Manager
	telemetryAPI *telemetry.APIHandler
	mux          *http.ServeMux
}

// NewAPIServer creates a new API server.
func NewAPIServer(storage *telemetry.Storage, interceptor *Interceptor, engine rules.RuleEvaluator, manager *Manager) *APIServer {
	s := &APIServer{
		storage:      storage,
		interceptor:  interceptor,
		engine:       engine,
		manager:      manager,
		telemetryAPI: telemetry.NewAPIHandler(storage),
		mux:          http.NewServeMux(),
	}

	s.registerRoutes()
	return s
}

// Management API route group prefixes (relative to /api).
var apiGroups = []string{"/security", "/telemetry", "/crust"}

// APIPrefixes returns the top-level path prefixes registered under /api.
func APIPrefixes() []string {
	prefixes := make([]string, len(apiGroups))
	for i, g := range apiGroups {
		prefixes[i] = "/api" + g + "/"
	}
	return prefixes
}

// Handler returns the HTTP handler with middleware applied.
func (s *APIServer) Handler() http.Handler {
	return api.Chain(s.mux, []func(http.Handler) http.Handler{
		api.Recovery,
		api.SecurityHeaders,
		func(next http.Handler) http.Handler {
			return api.BodySizeLimit(api.MaxBodySize, next)
		},
	})
}

func (s *APIServer) registerRoutes() {
	// Health check
	s.mux.HandleFunc("GET /health", s.handleHealth)

	// Security routes
	s.mux.HandleFunc("GET /api/security/logs", s.handleLogs)
	s.mux.HandleFunc("GET /api/security/stats", s.handleStats)
	s.mux.HandleFunc("GET /api/security/status", s.handleStatus)
	s.mux.HandleFunc("GET /api/security/events/stream", s.handleEventsStream)
	s.mux.HandleFunc("GET /api/security/changes/stream", s.handleChangesStream)
	s.mux.HandleFunc("GET /api/security/plugins", s.handlePlugins)
	s.mux.HandleFunc("GET /api/security/agents", s.handleAgents)

	// Telemetry routes
	s.mux.HandleFunc("GET /api/telemetry/traces", s.telemetryAPI.HandleTraces)
	s.mux.HandleFunc("GET /api/telemetry/traces/{trace_id}", s.telemetryAPI.HandleTrace)
	s.mux.HandleFunc("GET /api/telemetry/stats", s.telemetryAPI.HandleStats)
	s.mux.HandleFunc("GET /api/telemetry/sessions", s.telemetryAPI.HandleSessions)
	s.mux.HandleFunc("GET /api/telemetry/sessions/{session_id}/events", s.telemetryAPI.HandleSessionEvents)

	// Stats aggregation — already net/http handlers
	statsHandlers := s.telemetryAPI.StatsAggHandlers()
	s.mux.HandleFunc("GET /api/telemetry/stats/trend", statsHandlers.HandleBlockTrend)
	s.mux.HandleFunc("GET /api/telemetry/stats/distribution", statsHandlers.HandleDistribution)
	s.mux.HandleFunc("GET /api/telemetry/stats/coverage", statsHandlers.HandleCoverage)

	// Rules routes
	if eng, ok := s.engine.(*rules.Engine); ok && eng != nil {
		rulesAPI := rules.NewAPIHandler(eng)
		s.mux.HandleFunc("GET /api/crust/rules", rulesAPI.HandleRules)
		s.mux.HandleFunc("GET /api/crust/rules/builtin", rulesAPI.HandleBuiltinRules)
		s.mux.HandleFunc("GET /api/crust/rules/user", rulesAPI.HandleUserRules)
		s.mux.HandleFunc("DELETE /api/crust/rules/user/{filename}", rulesAPI.HandleDeleteUserRuleFile)
		s.mux.HandleFunc("POST /api/crust/rules/reload", rulesAPI.HandleReload)
		s.mux.HandleFunc("POST /api/crust/rules/validate", rulesAPI.HandleValidate)
		s.mux.HandleFunc("GET /api/crust/rules/files", rulesAPI.HandleListFiles)
		s.mux.HandleFunc("POST /api/crust/rules/files", rulesAPI.HandleAddFile)
	}
}

func queryInt(r *http.Request, key string, defaultVal, maxVal int) int {
	s := r.URL.Query().Get(key)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 1 {
		return defaultVal
	}
	if v > maxVal {
		return maxVal
	}
	return v
}

// handleLogs handles GET /api/security/logs.
func (s *APIServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	minutes := queryInt(r, "minutes", 60, 10080)
	limit := queryInt(r, "limit", 100, 1000)

	logs, err := s.storage.GetRecentLogs(r.Context(), minutes, limit)
	if err != nil {
		api.Error(w, http.StatusInternalServerError, "Failed to get logs")
		return
	}

	if logs == nil {
		logs = []telemetry.ToolCallLog{}
	}

	api.Success(w, telemetry.SanitizeToolCallLogs(logs))
}

// handleStats handles GET /api/security/stats.
func (s *APIServer) handleStats(w http.ResponseWriter, _ *http.Request) {
	m := eventlog.GetMetrics()
	blocked := m.ProxyRequestBlocks.Load() + m.ProxyResponseBlocks.Load()

	api.Success(w, map[string]any{
		"total_tool_calls":       m.TotalToolCalls.Load(),
		"blocked_tool_calls":     blocked,
		"allowed_tool_calls":     m.ProxyResponseAllowed.Load(),
		"proxy_request_blocks":   m.ProxyRequestBlocks.Load(),
		"proxy_response_blocks":  m.ProxyResponseBlocks.Load(),
		"proxy_response_allowed": m.ProxyResponseAllowed.Load(),
	})
}

// handleStatus handles GET /api/security/status.
func (s *APIServer) handleStatus(w http.ResponseWriter, _ *http.Request) {
	ruleCount := 0
	lockedCount := 0
	if s.engine != nil {
		ruleCount = s.engine.RuleCount()
		if eng, ok := s.engine.(*rules.Engine); ok {
			lockedCount = eng.LockedRuleCount()
		}
	}

	enabled := false
	if s.interceptor != nil {
		enabled = s.interceptor.IsEnabled()
	}

	api.Success(w, map[string]any{
		"enabled":            enabled,
		"rules_count":        ruleCount,
		"locked_rules_count": lockedCount,
		"timestamp":          time.Now().UTC().Format(time.RFC3339),
	})
}

// handleEventsStream handles GET /api/security/events/stream (SSE).
func (s *APIServer) handleEventsStream(w http.ResponseWriter, r *http.Request) {
	id, ch, err := eventlog.Subscribe(64)
	if err != nil {
		http.Error(w, "too many event stream connections", http.StatusServiceUnavailable)
		return
	}
	defer eventlog.Unsubscribe(id)

	if !initSSE(w) {
		return
	}

	ctx := r.Context()
	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-keepalive.C:
			if !sseKeepalive(w) {
				return
			}
		case event := <-ch:
			data, err := json.Marshal(map[string]any{
				"tool_name":       event.ToolName,
				"was_blocked":     event.WasBlocked,
				"blocked_by_rule": event.RuleName,
				"layer":           event.Layer,
				"protocol":        event.Protocol,
				"direction":       event.Direction,
				"method":          event.Method,
				"block_type":      event.BlockType,
				"api_type":        event.APIType.String(),
				"model":           event.Model,
				"trace_id":        string(event.TraceID),
				"session_id":      string(event.SessionID),
				"timestamp":       event.RecordedAt.Format(time.RFC3339),
			})
			if err != nil {
				continue
			}
			if err := mcpgateway.WriteSSEEvent(w, mcpgateway.SSEEvent{
				Type: "security-event",
				Data: string(data),
			}); err != nil {
				return
			}
		}
	}
}

// handleChangesStream handles GET /api/security/changes/stream (SSE).
func (s *APIServer) handleChangesStream(w http.ResponseWriter, r *http.Request) {
	mon := monitor.New()
	mon.Start()
	defer mon.Stop()

	if !initSSE(w) {
		return
	}

	ctx := r.Context()
	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-keepalive.C:
			if !sseKeepalive(w) {
				return
			}
		case change, ok := <-mon.Changes():
			if !ok {
				return
			}
			if err := mcpgateway.WriteSSEEvent(w, mcpgateway.SSEEvent{
				Type: string(change.Kind),
				Data: string(change.Payload),
			}); err != nil {
				return
			}
		}
	}
}

// initSSE sets SSE headers and sends the initial ":connected" comment.
func initSSE(w http.ResponseWriter) bool {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(":connected\n\n")); err != nil {
		return false
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	return true
}

// sseKeepalive sends an SSE comment to prevent idle connection drops.
func sseKeepalive(w http.ResponseWriter) bool {
	if _, err := w.Write([]byte(":keepalive\n\n")); err != nil {
		return false
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	return true
}

// handlePlugins handles GET /api/security/plugins.
func (s *APIServer) handlePlugins(w http.ResponseWriter, _ *http.Request) {
	if s.manager == nil {
		api.Success(w, []map[string]any{})
		return
	}
	registry := s.manager.GetRegistry()
	if registry == nil {
		api.Success(w, []map[string]any{})
		return
	}
	api.Success(w, registry.Stats())
}

// handleAgents handles GET /api/security/agents.
func (s *APIServer) handleAgents(w http.ResponseWriter, _ *http.Request) {
	agents := agentdetect.Detect()
	api.Success(w, agents)
}

// handleHealth handles GET /health.
func (s *APIServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("OK"))
}
