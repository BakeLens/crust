//go:build !libcrust

package security

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/BakeLens/crust/internal/agentdetect"
	"github.com/BakeLens/crust/internal/api"
	"github.com/BakeLens/crust/internal/eventlog"
	"github.com/BakeLens/crust/internal/mcpgateway"
	"github.com/BakeLens/crust/internal/monitor"
	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/telemetry"
)

// APIServer handles HTTP API requests for security management and telemetry
type APIServer struct {
	storage      *telemetry.Storage
	interceptor  *Interceptor
	engine       rules.RuleEvaluator
	manager      *Manager
	telemetryAPI *telemetry.APIHandler
	router       *gin.Engine
}

// NewAPIServer creates a new API server
func NewAPIServer(storage *telemetry.Storage, interceptor *Interceptor, engine rules.RuleEvaluator, manager *Manager) *APIServer {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	// Apply middleware in order
	router.Use(gin.Recovery())
	router.Use(api.SecurityHeadersMiddleware())
	router.Use(api.BodySizeLimitMiddleware(api.MaxBodySize)) // Limit request body size

	s := &APIServer{
		storage:      storage,
		interceptor:  interceptor,
		engine:       engine,
		manager:      manager,
		telemetryAPI: telemetry.NewAPIHandler(storage),
		router:       router,
	}

	s.registerRoutes()
	return s
}

// Management API route group prefixes (relative to /api).
// Used by both registerRoutes and APIPrefixes to stay in sync.
var apiGroups = []string{"/security", "/telemetry", "/crust"}

// APIPrefixes returns the top-level path prefixes registered under /api.
// Used by the mux in main.go to register only management routes so that
// /api/v1/... from LLM clients falls through to the proxy handler.
func APIPrefixes() []string {
	prefixes := make([]string, len(apiGroups))
	for i, g := range apiGroups {
		prefixes[i] = "/api" + g + "/"
	}
	return prefixes
}

// Handler returns the HTTP handler for the API
func (s *APIServer) Handler() http.Handler {
	return s.router
}

func (s *APIServer) registerRoutes() {
	// Health check
	s.router.GET("/health", s.handleHealth)

	// API routes
	apiGroup := s.router.Group("/api")
	{
		// Security routes
		security := apiGroup.Group(apiGroups[0])
		{
			security.GET("/logs", s.handleLogs)
			security.GET("/stats", s.handleStats)
			security.GET("/status", s.handleStatus)
			security.GET("/events/stream", s.handleEventsStream)
			security.GET("/changes/stream", s.handleChangesStream)
			security.GET("/plugins", s.handlePlugins)
			security.GET("/agents", s.handleAgents)
		}

		// Telemetry routes
		telemetryGroup := apiGroup.Group(apiGroups[1])
		{
			telemetryGroup.GET("/traces", s.telemetryAPI.HandleTraces)
			telemetryGroup.GET("/traces/:trace_id", s.telemetryAPI.HandleTrace)
			telemetryGroup.GET("/stats", s.telemetryAPI.HandleStats)
			telemetryGroup.GET("/sessions", s.telemetryAPI.HandleSessions)
			telemetryGroup.GET("/sessions/:session_id/events", s.telemetryAPI.HandleSessionEvents)

			// Stats aggregation endpoints — plain net/http handlers via StatsService
			statsHandlers := s.telemetryAPI.StatsAggHandlers()
			telemetryGroup.GET("/stats/trend", gin.WrapF(statsHandlers.HandleBlockTrend))
			telemetryGroup.GET("/stats/distribution", gin.WrapF(statsHandlers.HandleDistribution))
			telemetryGroup.GET("/stats/coverage", gin.WrapF(statsHandlers.HandleCoverage))
		}

		// Rules routes (if rule engine is available)
		if eng, ok := s.engine.(*rules.Engine); ok && eng != nil {
			rulesAPI := rules.NewAPIHandler(eng)
			rulesGroup := apiGroup.Group(apiGroups[2] + "/rules")
			{
				rulesGroup.GET("", rulesAPI.HandleRules)
				rulesGroup.GET("/builtin", rulesAPI.HandleBuiltinRules)
				rulesGroup.GET("/user", rulesAPI.HandleUserRules)
				rulesGroup.DELETE("/user/:filename", rulesAPI.HandleDeleteUserRuleFile)
				rulesGroup.POST("/reload", rulesAPI.HandleReload)
				rulesGroup.POST("/validate", rulesAPI.HandleValidate)
				rulesGroup.GET("/files", rulesAPI.HandleListFiles)
				rulesGroup.POST("/files", rulesAPI.HandleAddFile)
			}
		}
	}
}

// LogsQuery represents query parameters for logs endpoint
type LogsQuery struct {
	// SECURITY: Added max limits to prevent resource exhaustion
	Minutes int `form:"minutes" binding:"omitempty,min=1,max=10080"` // max 7 days
	Limit   int `form:"limit" binding:"omitempty,min=1,max=1000"`    // reduced from 10000
}

// handleLogs handles GET /api/security/logs
func (s *APIServer) handleLogs(c *gin.Context) {
	var query LogsQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		api.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	// Set defaults
	if query.Minutes == 0 {
		query.Minutes = 60
	}
	if query.Limit == 0 {
		query.Limit = 100
	}

	logs, err := s.storage.GetRecentLogs(c.Request.Context(), query.Minutes, query.Limit)
	if err != nil {
		api.Error(c, http.StatusInternalServerError, "Failed to get logs")
		return
	}

	if logs == nil {
		logs = []telemetry.ToolCallLog{}
	}

	api.Success(c, telemetry.SanitizeToolCallLogs(logs))
}

// handleStats handles GET /api/security/stats
// Returns in-memory metrics for the current daemon session (not DB totals).
func (s *APIServer) handleStats(c *gin.Context) {
	m := eventlog.GetMetrics()
	blocked := m.ProxyRequestBlocks.Load() + m.ProxyResponseBlocks.Load()

	api.Success(c, gin.H{
		"total_tool_calls":       m.TotalToolCalls.Load(),
		"blocked_tool_calls":     blocked,
		"allowed_tool_calls":     m.ProxyResponseAllowed.Load(),
		"proxy_request_blocks":   m.ProxyRequestBlocks.Load(),
		"proxy_response_blocks":  m.ProxyResponseBlocks.Load(),
		"proxy_response_allowed": m.ProxyResponseAllowed.Load(),
	})
}

// handleStatus handles GET /api/security/status
func (s *APIServer) handleStatus(c *gin.Context) {
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

	api.Success(c, gin.H{
		"enabled":            enabled,
		"rules_count":        ruleCount,
		"locked_rules_count": lockedCount,
		"timestamp":          time.Now().UTC().Format(time.RFC3339),
	})
}

// handleEventsStream handles GET /api/security/events/stream.
// Opens an SSE connection that pushes security events in real time.
// Events are delivered best-effort: slow clients may miss events.
// The connection closes when the client disconnects or the server shuts down.
//
// SSE frame format:
//
//	event: security-event
//	data: {"tool_name":"bash","was_blocked":true,"blocked_by_rule":"...","layer":"..."}
//
// Returns 503 if the maximum number of concurrent subscribers is reached.
func (s *APIServer) handleEventsStream(c *gin.Context) {
	id, ch, err := eventlog.Subscribe(64)
	if err != nil {
		c.String(http.StatusServiceUnavailable, "too many event stream connections")
		return
	}
	defer eventlog.Unsubscribe(id)

	if !initSSE(c) {
		return
	}

	ctx := c.Request.Context()
	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-keepalive.C:
			if !sseKeepalive(c) {
				return
			}
		case event := <-ch:
			// Reuse the same field mapping as record.go → telemetry.ToolCallLog,
			// but strip Arguments for security (same as SanitizeToolCallLogs).
			data, err := json.Marshal(gin.H{
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
			if err := mcpgateway.WriteSSEEvent(c.Writer, mcpgateway.SSEEvent{
				Type: "security-event",
				Data: string(data),
			}); err != nil {
				return
			}
		}
	}
}

// handleChangesStream handles GET /api/security/changes/stream.
// Opens an SSE connection that streams unified change events from the monitor
// package. Each change is sent as an SSE event where the event type is the
// change kind (agents, event, session, protect) and the data is the JSON payload.
// The connection closes when the client disconnects or the server shuts down.
func (s *APIServer) handleChangesStream(c *gin.Context) {
	mon := monitor.New()
	mon.Start()
	defer mon.Stop()

	if !initSSE(c) {
		return
	}

	ctx := c.Request.Context()
	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-keepalive.C:
			if !sseKeepalive(c) {
				return
			}
		case change, ok := <-mon.Changes():
			if !ok {
				return
			}
			if err := mcpgateway.WriteSSEEvent(c.Writer, mcpgateway.SSEEvent{
				Type: string(change.Kind),
				Data: string(change.Payload),
			}); err != nil {
				return
			}
		}
	}
}

// initSSE sets SSE headers, sends the initial ":connected" comment, and flushes.
// Returns false if the initial write fails (client already disconnected).
func initSSE(c *gin.Context) bool {
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering
	c.Writer.WriteHeader(http.StatusOK)
	if _, err := c.Writer.Write([]byte(":connected\n\n")); err != nil {
		return false
	}
	if f, ok := c.Writer.(http.Flusher); ok {
		f.Flush()
	}
	return true
}

// sseKeepalive sends an SSE comment to prevent idle connection drops.
// Returns false if the write fails (client disconnected).
func sseKeepalive(c *gin.Context) bool {
	if _, err := c.Writer.Write([]byte(":keepalive\n\n")); err != nil {
		return false
	}
	if f, ok := c.Writer.(http.Flusher); ok {
		f.Flush()
	}
	return true
}

// handlePlugins handles GET /api/security/plugins.
// Returns health stats for all registered plugins (e.g., sandbox).
func (s *APIServer) handlePlugins(c *gin.Context) {
	if s.manager == nil {
		api.Success(c, []gin.H{})
		return
	}
	registry := s.manager.GetRegistry()
	if registry == nil {
		api.Success(c, []gin.H{})
		return
	}
	stats := registry.Stats()
	api.Success(c, stats)
}

// handleAgents handles GET /api/security/agents.
// Returns detected AI agent processes and their protection status.
func (s *APIServer) handleAgents(c *gin.Context) {
	agents := agentdetect.Detect()
	c.JSON(http.StatusOK, agents)
}

// handleHealth handles GET /health
func (s *APIServer) handleHealth(c *gin.Context) {
	c.String(http.StatusOK, "OK")
}
