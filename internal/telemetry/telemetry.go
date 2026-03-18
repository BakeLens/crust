package telemetry

import (
	"context"
	crypto_rand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/BakeLens/crust/internal/types"
)

const (
	// OpenInference semantic convention attributes
	AttrSpanKind        = "openinference.span.kind"
	AttrLLMModel        = "llm.model_name"
	AttrLLMProvider     = "llm.provider"
	AttrLLMIsStreaming  = "llm.is_streaming"
	AttrLLMTokensInput  = "llm.token_count.prompt"     //nolint:gosec // G101: attribute name, not credential
	AttrLLMTokensOutput = "llm.token_count.completion" //nolint:gosec // G101: attribute name, not credential
	AttrInputValue      = "input.value"
	AttrOutputValue     = "output.value"
	AttrHTTPStatusCode  = "http.status_code"
	AttrHTTPLatencyMs   = "http.latency_ms"
	AttrTargetURL       = "http.target_url"
	AttrToolName        = "tool.name"
	AttrToolParameters  = "tool.parameters"
	AttrTraceID         = "trace.id"

	// Span kinds
	SpanKindLLM  = "LLM"
	SpanKindTool = "TOOL"
)

// Config holds telemetry configuration
type Config struct {
	Enabled     bool
	ServiceName string
	SampleRate  float64
}

// ToolCall represents a tool call extracted from LLM response
type ToolCall struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// LLMSpanData contains all data to record for an LLM request
type LLMSpanData struct {
	TraceID      types.TraceID   // From X-Trace-ID header
	SessionID    types.SessionID // Derived from request messages
	SpanKind     string          // LLM, TOOL
	SpanName     string          // Custom span name
	Model        string          // Requested model name
	TargetURL    string          // Upstream URL
	Messages     json.RawMessage // Request body
	Response     json.RawMessage // Response body
	ToolCalls    []ToolCall      // Extracted tool calls
	InputTokens  int64
	OutputTokens int64
	Latency      time.Duration
	StatusCode   int
	IsStreaming  bool
}

// SpanContext holds span timing information
type SpanContext struct {
	TraceID   types.TraceID
	SpanID    types.SpanID
	Name      string
	StartTime time.Time
}

// Provider manages telemetry
type Provider struct {
	enabled     bool
	serviceName string
	sampleRate  float64
}

var (
	globalProvider *Provider
	globalStorage  Recorder
	globalMu       sync.RWMutex
)

// Init initializes the telemetry provider
func Init(ctx context.Context, cfg Config) (*Provider, error) {
	p := &Provider{
		enabled:     cfg.Enabled,
		serviceName: cfg.ServiceName,
		sampleRate:  cfg.SampleRate,
	}

	globalMu.Lock()
	globalProvider = p
	globalMu.Unlock()

	if cfg.Enabled {
		log.Debug("[TELEMETRY] Initialized (service=%s, sample_rate=%.2f)", cfg.ServiceName, cfg.SampleRate)
	}

	return p, nil
}

// Shutdown shuts down the provider
func (p *Provider) Shutdown(ctx context.Context) error {
	return nil
}

// IsEnabled returns whether telemetry is enabled
func (p *Provider) IsEnabled() bool {
	return p != nil && p.enabled
}

// GetGlobalProvider returns the global telemetry provider
func GetGlobalProvider() *Provider {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalProvider
}

// SetGlobalStorage sets the global storage for telemetry.
// Accepts any Recorder implementation (*Storage, NopRecorder, etc.).
func SetGlobalStorage(s Recorder) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalStorage = s
}

// GetGlobalStorage returns the global storage as a Recorder.
func GetGlobalStorage() Recorder {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalStorage
}

// StartLLMSpan starts a new span for an LLM request
func (p *Provider) StartLLMSpan(ctx context.Context, operationName string, traceID types.TraceID, spanName string) (context.Context, *SpanContext) {
	if p == nil || !p.enabled {
		return ctx, nil
	}

	if spanName != "" {
		operationName = spanName
	}

	spanCtx := &SpanContext{
		TraceID:   traceID,
		SpanID:    types.SpanID(generateSpanID()),
		Name:      operationName,
		StartTime: time.Now(),
	}

	return ctx, spanCtx
}

// EndLLMSpan ends the span and records all data to SQLite atomically.
func (p *Provider) EndLLMSpan(spanCtx *SpanContext, data LLMSpanData) {
	if p == nil || !p.enabled || spanCtx == nil {
		return
	}

	storage := GetGlobalStorage()
	if storage == nil {
		log.Debug("[TELEMETRY] Warning: storage not available, skipping span")
		return
	}

	// Build attributes
	attrs := map[string]any{
		AttrSpanKind:        data.SpanKind,
		AttrLLMModel:        data.Model,
		AttrTargetURL:       SanitizeTargetURL(data.TargetURL),
		AttrLLMIsStreaming:  data.IsStreaming,
		AttrLLMTokensInput:  data.InputTokens,
		AttrLLMTokensOutput: data.OutputTokens,
		AttrHTTPStatusCode:  data.StatusCode,
		AttrHTTPLatencyMs:   data.Latency.Milliseconds(),
		AttrTraceID:         data.TraceID,
	}

	if len(data.Messages) > 0 {
		attrs[AttrInputValue] = truncateString(string(data.Messages), 32000)
	}
	if len(data.Response) > 0 {
		attrs[AttrOutputValue] = truncateString(string(data.Response), 32000)
	}

	attrsJSON, err := json.Marshal(attrs)
	if err != nil {
		log.Debug("Failed to marshal span attributes: %v", err)
		attrsJSON = []byte("{}")
	}

	// Determine status code
	statusCode := "OK"
	if data.StatusCode >= 400 {
		statusCode = "ERROR"
	}

	spanKind := data.SpanKind
	if spanKind == "" {
		spanKind = SpanKindLLM
	}

	// Build main span
	mainSpan := &Span{
		SpanID:       spanCtx.SpanID,
		Name:         spanCtx.Name,
		SpanKind:     spanKind,
		StartTime:    spanCtx.StartTime,
		EndTime:      time.Now(),
		Attributes:   attrsJSON,
		InputTokens:  data.InputTokens,
		OutputTokens: data.OutputTokens,
		StatusCode:   statusCode,
	}

	// Build tool spans
	var toolSpans []*Span
	for _, tc := range data.ToolCalls {
		toolSpans = append(toolSpans, p.buildToolSpan(spanCtx.SpanID, data.TraceID, tc))
	}

	// Record everything atomically in a single transaction.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := storage.RecordSpanTx(ctx, data.TraceID, data.SessionID, mainSpan, toolSpans); err != nil {
		log.Debug("[TELEMETRY] Failed to record span: %v", err)
	}
}

// buildToolSpan creates a Span struct for a tool call without writing to the DB.
func (p *Provider) buildToolSpan(parentSpanID types.SpanID, traceID types.TraceID, tc ToolCall) *Span {
	attrs := map[string]any{
		AttrSpanKind:       SpanKindTool,
		AttrToolName:       tc.Name,
		AttrToolParameters: truncateString(string(tc.Arguments), 4000),
		AttrTraceID:        traceID,
	}
	attrsJSON, err := json.Marshal(attrs)
	if err != nil {
		log.Debug("Failed to marshal tool span attributes: %v", err)
		attrsJSON = []byte("{}")
	}

	return &Span{
		SpanID:       types.SpanID(generateSpanID()),
		ParentSpanID: parentSpanID,
		Name:         "tool:" + tc.Name,
		SpanKind:     SpanKindTool,
		StartTime:    time.Now(),
		EndTime:      time.Now(),
		Attributes:   attrsJSON,
		StatusCode:   "OK",
	}
}

func truncateString(s string, maxLen int) string {
	if maxLen <= 0 {
		if s == "" {
			return ""
		}
		return "...[truncated]"
	}
	if len(s) <= maxLen {
		return s
	}
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "...[truncated]"
}

// generateSpanID generates a cryptographically secure span ID.
// crypto/rand.Read never returns an error on modern platforms (Linux 3.17+,
// macOS, Windows), so the fallback is purely defensive. If it ever fires,
// we panic rather than silently producing a predictable ID that could
// collide or be guessed.
func generateSpanID() string {
	b := make([]byte, 8)
	if _, err := crypto_rand.Read(b); err != nil {
		panic("crypto/rand.Read failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
