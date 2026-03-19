package httpproxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/BakeLens/crust/internal/config"
	"github.com/BakeLens/crust/internal/eventlog"
	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/message"
	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/security"
	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/types"
)

var log = logger.New("proxy")

const encodingGzip = "gzip"

// requestBody represents minimal structure to extract model and messages
type requestBody struct {
	Model    string           `json:"model"`
	Stream   bool             `json:"stream"`
	Messages []requestMessage `json:"messages"`
	Tools    []toolDefinition `json:"tools,omitempty"`
	Input    json.RawMessage  `json:"input,omitempty"` // Responses API: input items
}

// toolDefinition represents a tool definition in the request
type toolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"` // Anthropic format
	Parameters  json.RawMessage `json:"parameters,omitempty"`   // OpenAI format
}

// requestMessage represents a message in the request
type requestMessage struct {
	Role    types.MessageRole `json:"role"`
	Content json.RawMessage   `json:"content"`
}

// ContentString returns the message content as a plain string.
// If Content is a JSON string, it returns the unquoted string.
// If Content is an array or other type, it returns the raw JSON text.
func (m requestMessage) ContentString() string {
	if len(m.Content) == 0 {
		return ""
	}
	// Try to unmarshal as a plain string first
	var s string
	if err := json.Unmarshal(m.Content, &s); err == nil {
		return s
	}
	// Fallback: return raw JSON (for array content parts, etc.)
	return string(m.Content)
}

// UsageResponse represents usage info from API responses
type UsageResponse struct {
	// Anthropic format
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
	// OpenAI format
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
}

// ResponseWithUsage represents API response with usage field
type ResponseWithUsage struct {
	Usage UsageResponse `json:"usage"`
}

// Proxy is the transparent proxy that captures telemetry
type Proxy struct {
	upstreamURL   *url.URL
	apiKey        string
	client        *http.Client
	userProviders map[string]config.ProviderConfig // user-defined keyword → provider config
	autoMode      bool                             // true = resolve provider from model name; false = always use upstreamURL
	interceptor   *security.Interceptor            // injected; nil disables security scanning
	secCfg        security.InterceptionConfig      // injected security configuration
}

// NewProxy creates a new proxy
func NewProxy(upstreamURL string, apiKey string, timeout time.Duration, userProviders map[string]config.ProviderConfig, autoMode bool, interceptor *security.Interceptor, secCfg security.InterceptionConfig) (*Proxy, error) {
	u, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, err
	}

	return &Proxy{
		upstreamURL:   u,
		apiKey:        apiKey,
		userProviders: userProviders,
		autoMode:      autoMode,
		interceptor:   interceptor,
		secCfg:        secCfg,
		client: &http.Client{
			// Do NOT set http.Client.Timeout — it covers the entire response
			// lifecycle including body reads, which kills long-running SSE
			// streams. Instead, use Transport-level timeouts that only apply
			// to connection setup and waiting for the first response byte.
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment, // Respect system proxy (HTTP_PROXY, HTTPS_PROXY, etc.)
				// SECURITY: Enforce TLS 1.2+ for upstream connections
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
				ForceAttemptHTTP2:     true, // Required: custom TLSClientConfig disables auto-HTTP/2
				DisableCompression:    true, // Preserve client's original Accept-Encoding
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: timeout, // Time to wait for server's first response byte
			},
			// Don't follow redirects automatically
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// doRequest performs an HTTP request and guarantees a non-nil *http.Response on success.
func (p *Proxy) doRequest(req *http.Request) (*http.Response, error) {
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("nil response from upstream")
	}
	return resp, nil
}

// Header length limits for security
const (
	maxTraceIDLen       = 128
	maxSpanNameLen      = 256
	maxSpanKindLen      = 32
	maxRequestBodySize  = 100 * 1024 * 1024 // 100MB - generous limit for LLM API requests
	maxResponseBodySize = 100 * 1024 * 1024 // 100MB - generous limit for LLM API responses
	maxErrorBodySize    = 1 * 1024 * 1024   // 1MB - error responses should be small
)

// sanitizeHeader truncates and sanitizes header values
func sanitizeHeader(value string, maxLen int) string {
	if len(value) > maxLen {
		return value[:maxLen]
	}
	return value
}

// ServeHTTP handles all incoming requests
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Extract and sanitize telemetry headers
	// SECURITY: Limit header lengths to prevent resource exhaustion
	traceID := types.TraceID(sanitizeHeader(r.Header.Get("X-Trace-Id"), maxTraceIDLen))
	spanName := sanitizeHeader(r.Header.Get("X-Span-Name"), maxSpanNameLen)
	spanKind := sanitizeHeader(r.Header.Get("X-Span-Kind"), maxSpanKindLen)

	// Fallback to W3C traceparent
	if traceID == "" {
		if traceparent := r.Header.Get("Traceparent"); traceparent != "" {
			// W3C traceparent format: version-trace_id-parent_id-flags
			// Validate format before parsing
			if len(traceparent) <= 256 {
				parts := strings.Split(traceparent, "-")
				if len(parts) >= 2 && len(parts[1]) <= maxTraceIDLen {
					traceID = types.TraceID(parts[1])
				}
			}
		}
	}

	bodyBytes, parseBytes, reqBody, ok := readAndDecompressBody(w, r)
	if !ok {
		return
	}

	// Save decompressed request body for telemetry (human-readable JSON)
	requestBody := make([]byte, len(parseBytes))
	copy(requestBody, parseBytes)

	// Compute session ID from messages (system prompt + first user message)
	sessionID := types.SessionID(computeSessionID(reqBody.Messages))
	if sessionID.IsEmpty() {
		sessionID = types.SessionID(traceID) // fallback to traceID if no messages
	}

	// Strip /api prefix sent by some IDE clients before any
	// path-based logic so detectAPIType and buildUpstreamURL both see
	// the canonical path.
	reqPath := stripAPIPrefix(r.URL.Path)

	// Determine API type from path
	apiType := detectAPIType(reqPath)

	// [Layer0] Scan tool_calls in request history (format-agnostic).
	// Walks raw JSON to find tool calls across OpenAI Chat, Anthropic Messages,
	// and OpenAI Responses formats without format-specific struct parsing.
	interceptor := p.interceptor
	if interceptor != nil && interceptor.IsEnabled() && interceptor.GetEngine() != nil {
		for _, tc := range extractToolCallsFromJSON(parseBytes) {
			result := interceptor.GetEngine().Evaluate(tc)
			if result.Matched && result.Action == rules.ActionBlock {
				log.Warn("[Layer0] Request blocked: %s in history (rule: %s)", tc.Name, result.RuleName)
				eventlog.Record(eventlog.Event{
					Layer:      eventlog.LayerProxyRequest,
					TraceID:    traceID,
					SessionID:  sessionID,
					ToolName:   tc.Name,
					Arguments:  tc.Arguments,
					APIType:    apiType,
					Model:      reqBody.Model,
					WasBlocked: true,
					RuleName:   result.RuleName,
				})
				http.Error(w, message.FormatHTTPBlock(result), http.StatusForbidden)
				return
			}
		}
	}

	// Start telemetry span
	tp := telemetry.GetGlobalProvider()
	var spanCtx *telemetry.SpanContext
	var ctx context.Context

	if tp != nil && tp.IsEnabled() {
		ctx, spanCtx = tp.StartLLMSpan(r.Context(), "llm.request", traceID, spanName)
	} else {
		ctx = r.Context()
	}

	upstreamReq, targetURLStr, providerAPIKey, ok := p.prepareUpstreamRequest(
		ctx, w, r, reqPath, reqBody.Model, bodyBytes, apiType,
	)
	if !ok {
		return
	}

	// For streaming requests, use reverse proxy for better streaming support
	if reqBody.Stream {
		ctx := &RequestContext{
			Writer:         w,
			Request:        r,
			UpstreamReq:    upstreamReq,
			BodyBytes:      bodyBytes,
			RequestBody:    requestBody,
			StartTime:      startTime,
			TraceID:        traceID,
			SessionID:      sessionID,
			SpanName:       spanName,
			SpanKind:       spanKind,
			Model:          reqBody.Model,
			TargetURL:      targetURLStr,
			APIType:        apiType,
			Tools:          reqBody.Tools,
			ProviderAPIKey: providerAPIKey,
			Provider:       tp,
			SpanCtx:        spanCtx,
		}
		p.handleStreamingRequest(ctx)
		return
	}

	// Non-streaming: use http.Client directly
	resp, err := p.doRequest(upstreamReq)
	if err != nil {
		log.Error("Upstream request failed: %v", err)

		if tp != nil && tp.IsEnabled() && spanCtx != nil {
			tp.EndLLMSpan(spanCtx, telemetry.LLMSpanData{
				TraceID:    traceID,
				SessionID:  sessionID,
				Model:      reqBody.Model,
				TargetURL:  targetURLStr,
				Messages:   requestBody,
				Latency:    time.Since(startTime),
				StatusCode: 502,
			})
		}

		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	responseBody, inputTokens, outputTokens, toolCalls := processNonStreamingResponse(
		resp, apiType, traceID, sessionID, reqBody.Model, p.interceptor, p.secCfg,
	)

	duration := time.Since(startTime)

	log.Info("%s %s model=%s → %s status=%d duration=%v tokens=%d/%d tools=%d",
		r.Method, r.URL.Path, reqBody.Model, targetURLStr, resp.StatusCode, duration, inputTokens, outputTokens, len(toolCalls))

	// Record telemetry
	if tp != nil && tp.IsEnabled() && spanCtx != nil {
		tp.EndLLMSpan(spanCtx, telemetry.LLMSpanData{
			TraceID:      traceID,
			SessionID:    sessionID,
			SpanKind:     spanKind,
			SpanName:     spanName,
			Model:        reqBody.Model,
			TargetURL:    targetURLStr,
			Messages:     requestBody,
			Response:     responseBody,
			ToolCalls:    toolCalls,
			InputTokens:  inputTokens,
			OutputTokens: outputTokens,
			Latency:      duration,
			StatusCode:   resp.StatusCode,
			IsStreaming:  false,
		})
	}

	// Copy response headers and fix Content-Length before writing the status
	// (headers cannot be modified after WriteHeader is called).
	copyHeaders(w.Header(), resp.Header)
	w.Header().Set("Content-Length", strconv.Itoa(len(responseBody)))
	w.WriteHeader(resp.StatusCode)
	writeBody(w, responseBody)
}

// readAndDecompressBody reads the request body with size limits, decompresses
// gzip/zstd for local security scanning (forwarding original bytes upstream),
// and parses the JSON. Returns ok=false if an HTTP error was already written.
func readAndDecompressBody(w http.ResponseWriter, r *http.Request) (
	bodyBytes, parseBytes []byte, reqBody requestBody, ok bool,
) {
	// Read request body with size limit to prevent DoS
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok { //nolint:errcheck // AsType returns (E, bool), not error
			log.Warn("Request body too large (limit: %dMB)", maxRequestBodySize/(1024*1024))
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return nil, nil, requestBody{}, false
		}
		log.Error("Failed to read request body: %v", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return nil, nil, requestBody{}, false
	}
	_ = r.Body.Close()

	// Decompress request body for local parsing only (model extraction, security scanning).
	// The original compressed body is forwarded to upstream untouched for full transparency.
	parseBytes = bodyBytes
	if len(bodyBytes) >= 4 {
		contentEncoding := r.Header.Get("Content-Encoding")
		if contentEncoding == "" {
			// Auto-detect by magic bytes
			if bodyBytes[0] == 0x1f && bodyBytes[1] == 0x8b {
				contentEncoding = encodingGzip
			} else if bodyBytes[0] == 0x28 && bodyBytes[1] == 0xb5 && bodyBytes[2] == 0x2f && bodyBytes[3] == 0xfd {
				contentEncoding = "zstd"
			}
		}
		switch contentEncoding {
		case encodingGzip:
			if gr, err := gzip.NewReader(bytes.NewReader(bodyBytes)); err == nil {
				if decompressed, err := io.ReadAll(io.LimitReader(gr, maxRequestBodySize+1)); err == nil {
					parseBytes = decompressed
				}
				if err := gr.Close(); err != nil {
					log.Debug("Failed to close gzip reader: %v", err)
				}
			}
		case "zstd":
			if decoder, err := zstd.NewReader(nil); err == nil {
				if decompressed, err := decoder.DecodeAll(bodyBytes, nil); err == nil {
					parseBytes = decompressed
				}
				decoder.Close()
			}
		}

		// Fail-closed: reject requests with unsupported Content-Encoding
		// that we couldn't decompress (prevents bypassing security scanning).
		// Only reject when a Content-Encoding header was present but we couldn't decode it.
		if contentEncoding != "" && bytes.Equal(parseBytes, bodyBytes) {
			log.Warn("Unsupported Content-Encoding %q — rejecting request", contentEncoding)
			http.Error(w, "Unsupported Content-Encoding: "+contentEncoding, http.StatusUnsupportedMediaType)
			return nil, nil, requestBody{}, false
		}
	}

	// Parse model name and messages (from decompressed bytes)
	if err := json.Unmarshal(parseBytes, &reqBody); err != nil && len(parseBytes) > 0 {
		log.Debug("Request body parse error: %v", err)
	}

	return bodyBytes, parseBytes, reqBody, true
}

// prepareUpstreamRequest builds the upstream URL, clones the incoming request,
// strips hop-by-hop headers, and injects authentication. Returns ok=false if
// an HTTP error was already written.
func (p *Proxy) prepareUpstreamRequest(
	ctx context.Context, w http.ResponseWriter, r *http.Request,
	reqPath, model string, bodyBytes []byte, apiType types.APIType,
) (upstreamReq *http.Request, targetURLStr, providerAPIKey string, ok bool) {
	upstreamURL, providerAPIKey, err := p.buildUpstreamURL(reqPath, model)
	if err != nil {
		log.Warn("Failed to build upstream URL: %v", err)
		http.Error(w, "invalid upstream URL", http.StatusBadGateway)
		return nil, "", "", false
	}
	upstreamURL.RawQuery = r.URL.RawQuery
	targetURLStr = upstreamURL.String()

	log.Debug("Forwarding %s %s model=%s → %s", r.Method, r.URL.Path, model, targetURLStr)

	// Clone original request for maximum transparency — preserves all headers,
	// trailers, and internal state exactly as the client sent them.
	targetURL, err := url.Parse(targetURLStr)
	if err != nil {
		http.Error(w, "invalid upstream URL", http.StatusBadGateway)
		return nil, "", "", false
	}
	upstreamReq = r.Clone(ctx)
	upstreamReq.URL = targetURL
	upstreamReq.Host = targetURL.Host
	upstreamReq.RequestURI = "" // required for http.Client.Do()
	upstreamReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	upstreamReq.ContentLength = int64(len(bodyBytes))

	// Remove hop-by-hop headers (including Connection-listed per RFC 7230 §6.1)
	stripHopByHopHeaders(upstreamReq.Header)

	injectAuth(upstreamReq.Header, providerAPIKey, p.apiKey, apiType.IsAnthropic())

	return upstreamReq, targetURLStr, providerAPIKey, true
}

// processNonStreamingResponse reads the response body, extracts token usage
// and tool calls, and applies Layer 1 security interception.
func processNonStreamingResponse(
	resp *http.Response, apiType types.APIType,
	traceID types.TraceID, sessionID types.SessionID, model string,
	interceptor *security.Interceptor, secCfg security.InterceptionConfig,
) (responseBody []byte, inputTokens, outputTokens int64, toolCalls []telemetry.ToolCall) {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		inputTokens, outputTokens, responseBody = extractUsageAndBody(resp, apiType)
		toolCalls = extractToolCalls(responseBody, apiType)

		// Security interception for non-streaming responses
		if interceptor != nil && interceptor.IsEnabled() && len(toolCalls) > 0 {
			result, err := interceptor.InterceptToolCalls(responseBody, security.InterceptionContext{
				TraceID:   traceID,
				SessionID: sessionID,
				Model:     model,
				APIType:   apiType,
				BlockMode: secCfg.BlockMode,
			})
			if err != nil {
				log.Warn("Security interception error: %v", err)
			} else {
				responseBody = result.ModifiedResponse
				if len(result.BlockedToolCalls) > 0 {
					log.Info("Blocked %d tool calls", len(result.BlockedToolCalls))
				}
				toolCalls = result.AllowedToolCalls
			}
		}
	} else {
		var err error
		responseBody, err = io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize+1))
		if err != nil {
			log.Warn("Failed to read error response body: %v", err)
		}
		if int64(len(responseBody)) > maxErrorBodySize {
			log.Warn("Error response body too large, truncating to %dKB", maxErrorBodySize/1024)
			responseBody = responseBody[:maxErrorBodySize]
		}
	}
	return
}

// Some IDE clients prepend /api/ when targeting an OpenAI-compatible
// endpoint. Only strips when "/api" is followed by "/" or is the entire
// path — "/apis/..." is left untouched.
func stripAPIPrefix(path string) string {
	if path == "/api" {
		return "/"
	}
	if after, ok := strings.CutPrefix(path, "/api/"); ok {
		return "/" + after
	}
	return path
}

// detectAPIType detects the API type from the request path
func detectAPIType(path string) types.APIType {
	if strings.Contains(path, "/anthropic") || strings.Contains(path, "/v1/messages") {
		return types.APITypeAnthropic
	}
	if strings.Contains(path, "/v1/responses") || strings.HasSuffix(path, "/responses") {
		return types.APITypeOpenAIResponses
	}
	return types.APITypeOpenAICompletion
}

// hasClientAuth returns true if the request already carries an auth header.
func hasClientAuth(h http.Header) bool {
	return h.Get("Authorization") != "" || h.Get("X-Api-Key") != ""
}

// injectAuth sets auth headers on the request. Per-provider key always wins,
// then client auth passthrough, then global gateway key as fallback.
func injectAuth(h http.Header, providerKey, gatewayKey string, isAnthropic bool) {
	if providerKey != "" {
		if isAnthropic {
			h.Set("X-Api-Key", providerKey)
			h.Del("Authorization")
		} else {
			h.Set("Authorization", "Bearer "+providerKey)
			h.Del("X-Api-Key")
		}
	} else if !hasClientAuth(h) && gatewayKey != "" {
		if isAnthropic {
			h.Set("X-Api-Key", gatewayKey)
		} else {
			h.Set("Authorization", "Bearer "+gatewayKey)
		}
	}
}

// buildUpstreamURL constructs the target URL for a proxy request.
// In auto mode it resolves the provider from the model name; in endpoint mode
// it always uses the configured upstream URL.
// Returns the target URL and an optional per-provider API key.
func (p *Proxy) buildUpstreamURL(reqPath, model string) (url.URL, string, error) {
	u := *p.upstreamURL

	if p.autoMode {
		// Auto mode: resolve provider from model name
		if result, ok := ResolveProvider(model, p.userProviders); ok {
			resolvedURL, err := url.Parse(result.URL)
			if err != nil {
				return url.URL{}, "", fmt.Errorf("invalid provider URL %q: %w", result.URL, err)
			}
			// Normalize /responses → /v1/responses only when the provider
			// has no meaningful path (e.g. "https://api.openai.com").
			// Providers with a path (e.g. "chatgpt.com/backend-api/codex")
			// get the request path appended directly.
			if reqPath == "/responses" && (resolvedURL.Path == "" || resolvedURL.Path == "/") {
				reqPath = "/v1/responses"
			}
			u.Scheme = resolvedURL.Scheme
			u.Host = resolvedURL.Host
			// If the provider URL already contains an API version segment
			// (e.g. /v4 in "open.bigmodel.cn/api/paas/v4"), strip the
			// client's version prefix to avoid path duplication like
			// /api/paas/v4/v1/chat/completions.
			if pathHasVersion(resolvedURL.Path) {
				reqPath = stripLeadingVersion(reqPath)
			}
			u.Path = path.Join(resolvedURL.Path, reqPath)
			return u, result.APIKey, nil
		}
	}

	// Endpoint mode (or auto mode with unrecognized model):
	// Append reqPath to the base URL's path so that upstream base paths
	// (e.g. "https://openrouter.ai/api") are preserved.
	if reqPath == "/responses" {
		reqPath = "/v1/responses"
	}
	basePath := strings.TrimSuffix(u.Path, "/")
	// Deduplicate when reqPath already starts with the base path
	// (e.g. base="/v1", req="/v1/chat/completions" → "/v1/chat/completions").
	if basePath != "" && strings.HasPrefix(reqPath, basePath+"/") {
		u.Path = reqPath
	} else {
		if pathHasVersion(basePath) {
			reqPath = stripLeadingVersion(reqPath)
		}
		u.Path = path.Join(u.Path, reqPath)
	}
	return u, "", nil
}

// pathHasVersion reports whether any segment of the URL path starts with
// an API version prefix — "v" followed by at least one digit (e.g. "v1",
// "v4", "v1beta", "v2alpha1").  This detects provider URLs such as
// "open.bigmodel.cn/api/paas/v4" and "generativelanguage.googleapis.com/v1beta/openai".
// When detected, the client's redundant /vN prefix is stripped by
// stripLeadingVersion to avoid path duplication.
func pathHasVersion(p string) bool {
	for seg := range strings.SplitSeq(p, "/") {
		if len(seg) >= 2 && seg[0] == 'v' && seg[1] >= '0' && seg[1] <= '9' {
			return true
		}
	}
	return false
}

// stripLeadingVersion removes a leading /vN segment from a request path.
// e.g. "/v1/chat/completions" → "/chat/completions".
// Returns the path unchanged if it does not start with a version segment.
func stripLeadingVersion(p string) string {
	if len(p) < 3 || p[0] != '/' || p[1] != 'v' {
		return p
	}
	i := 2
	for i < len(p) && p[i] >= '0' && p[i] <= '9' {
		i++
	}
	if i == 2 {
		return p // no digits after 'v'
	}
	if i >= len(p) {
		return "/" // entire path was just "/vN"
	}
	if p[i] == '/' {
		return p[i:]
	}
	return p // not a pure version segment (e.g. "/v1beta/...")
}

// extractUsageAndBody extracts token usage and body from response
func extractUsageAndBody(resp *http.Response, apiType types.APIType) (inputTokens, outputTokens int64, bodyBytes []byte) {
	if resp == nil {
		return 0, 0, nil
	}
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		var err error
		bodyBytes, err = io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize+1))
		if err != nil {
			log.Debug("Failed to read non-JSON response body: %v", err)
		}
		if int64(len(bodyBytes)) > maxResponseBodySize {
			log.Warn("Non-JSON response body too large (limit: %dMB)", maxResponseBodySize/(1024*1024))
			bodyBytes = nil
		}
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return 0, 0, bodyBytes
	}

	// Read the entire raw body first so we have it available as fallback on gzip error
	rawBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize+1))
	if err != nil {
		log.Debug("Failed to read response body: %v", err)
		resp.Body = io.NopCloser(bytes.NewReader(nil))
		return 0, 0, nil
	}
	if int64(len(rawBytes)) > maxResponseBodySize {
		log.Warn("Response body too large (limit: %dMB)", maxResponseBodySize/(1024*1024))
		resp.Body = io.NopCloser(bytes.NewReader(nil))
		return 0, 0, nil
	}

	bodyBytes = rawBytes

	if resp.Header.Get("Content-Encoding") == encodingGzip {
		gzReader, err := gzip.NewReader(bytes.NewReader(rawBytes))
		if err != nil {
			log.Debug("Failed to create gzip reader, using raw body: %v", err)
			resp.Header.Del("Content-Encoding")
		} else {
			decompressed, readErr := io.ReadAll(io.LimitReader(gzReader, maxResponseBodySize+1))
			_ = gzReader.Close()
			if readErr != nil {
				log.Debug("Failed to decompress gzip body, using raw body: %v", readErr)
				resp.Header.Del("Content-Encoding")
			} else if int64(len(decompressed)) > maxResponseBodySize {
				log.Warn("Decompressed response body too large (limit: %dMB)", maxResponseBodySize/(1024*1024))
				resp.Header.Del("Content-Encoding")
			} else {
				bodyBytes = decompressed
				resp.Header.Del("Content-Encoding")
			}
		}
	}

	var respData ResponseWithUsage
	if err := json.Unmarshal(bodyBytes, &respData); err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return 0, 0, bodyBytes
	}

	switch apiType {
	case types.APITypeAnthropic, types.APITypeOpenAIResponses:
		inputTokens = respData.Usage.InputTokens
		outputTokens = respData.Usage.OutputTokens
	case types.APITypeOpenAICompletion:
		inputTokens = respData.Usage.PromptTokens
		outputTokens = respData.Usage.CompletionTokens
	case types.APITypeUnknown:
		// no usage data for unknown types
	}

	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	resp.ContentLength = int64(len(bodyBytes))

	return inputTokens, outputTokens, bodyBytes
}
