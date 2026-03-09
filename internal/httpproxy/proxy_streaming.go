package httpproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httputil"
	"strconv"
	"time"

	"github.com/BakeLens/crust/internal/security"
	"github.com/BakeLens/crust/internal/telemetry"
)

// handleStreamingRequest handles SSE streaming requests
func (p *Proxy) handleStreamingRequest(ctx *RequestContext) {
	// Auto-buffer: only buffer when security buffering is enabled AND the
	// request carries tool definitions. Pure text-generation streams can
	// never produce tool calls, so buffering them adds latency for zero
	// security benefit.
	secCfg := security.GetInterceptionConfig()
	if secCfg.BufferStreaming && len(ctx.Tools) > 0 {
		p.handleBufferedStreamingRequest(ctx, secCfg)
		return
	}

	// Use reverse proxy for non-buffered streaming
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL = ctx.UpstreamReq.URL
			pr.Out.Host = ctx.UpstreamReq.URL.Host
			copyHeaders(pr.Out.Header, ctx.UpstreamReq.Header)
			pr.Out.Body = io.NopCloser(bytes.NewReader(ctx.BodyBytes))
			pr.Out.ContentLength = int64(len(ctx.BodyBytes))
			injectAuth(pr.Out.Header, ctx.ProviderAPIKey, p.apiKey, ctx.APIType.IsAnthropic())
		},
		ModifyResponse: func(resp *http.Response) error {
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				resp.Body = NewSSEReaderWithSecurity(resp.Body, ctx.APIType, ctx.TraceID, ctx.SessionID, ctx.Model, func(in, out int64, content string, toolCalls []telemetry.ToolCall) {
					duration := time.Since(ctx.StartTime)

					log.Info("%s %s model=%s → %s status=%d duration=%v tokens=%d/%d tools=%d [stream]",
						ctx.Request.Method, ctx.Request.URL.Path, ctx.Model, ctx.TargetURL, resp.StatusCode, duration, in, out, len(toolCalls))

					if ctx.Provider != nil && ctx.Provider.IsEnabled() && ctx.SpanCtx != nil {
						ctx.Provider.EndLLMSpan(ctx.SpanCtx, telemetry.LLMSpanData{
							TraceID:      ctx.TraceID,
							SessionID:    ctx.SessionID,
							SpanKind:     ctx.SpanKind,
							SpanName:     ctx.SpanName,
							Model:        ctx.Model,
							TargetURL:    ctx.TargetURL,
							Messages:     ctx.RequestBody,
							Response:     marshalContentJSON(content),
							ToolCalls:    toolCalls,
							InputTokens:  in,
							OutputTokens: out,
							Latency:      duration,
							StatusCode:   resp.StatusCode,
							IsStreaming:  true,
						})
					}
				})
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Error("Proxy error: %v", err)

			if ctx.Provider != nil && ctx.Provider.IsEnabled() && ctx.SpanCtx != nil {
				ctx.Provider.EndLLMSpan(ctx.SpanCtx, telemetry.LLMSpanData{
					TraceID:    ctx.TraceID,
					SessionID:  ctx.SessionID,
					Model:      ctx.Model,
					TargetURL:  ctx.TargetURL,
					Messages:   ctx.RequestBody,
					Latency:    time.Since(ctx.StartTime),
					StatusCode: 502,
				})
			}

			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
		FlushInterval: -1,
	}

	proxy.ServeHTTP(ctx.Writer, ctx.Request)
}

// handleBufferedStreamingRequest handles SSE streaming with response buffering for security evaluation.
// Headers are not written to the client until buffering completes, so that on buffer overflow we can
// fall back to a non-streaming retry (option 3) without having committed to SSE framing.
func (p *Proxy) handleBufferedStreamingRequest(ctx *RequestContext, secCfg security.InterceptionConfig) {
	// Make the upstream request
	resp, err := p.doRequest(ctx.UpstreamReq)
	if err != nil {
		log.Error("Upstream request failed: %v", err)
		if ctx.Provider != nil && ctx.Provider.IsEnabled() && ctx.SpanCtx != nil {
			ctx.Provider.EndLLMSpan(ctx.SpanCtx, telemetry.LLMSpanData{
				TraceID:    ctx.TraceID,
				SessionID:  ctx.SessionID,
				Model:      ctx.Model,
				TargetURL:  ctx.TargetURL,
				Messages:   ctx.RequestBody,
				Latency:    time.Since(ctx.StartTime),
				StatusCode: 502,
			})
		}
		http.Error(ctx.Writer, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// For non-2xx responses, log and proxy through immediately.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Info("%s %s model=%s → %s status=%d duration=%v [stream-error]",
			ctx.Request.Method, ctx.Request.URL.Path, ctx.Model, ctx.TargetURL, resp.StatusCode, time.Since(ctx.StartTime))
		copyHeaders(ctx.Writer.Header(), resp.Header)
		ctx.Writer.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(ctx.Writer, resp.Body)
		return
	}

	// Save upstream headers/status — we defer writing them to the client until
	// buffering finishes so we can switch to non-streaming format on overflow.
	savedStatus := resp.StatusCode
	savedHeaders := resp.Header.Clone()

	// Create buffered SSE writer with available tools.
	timeout := time.Duration(secCfg.BufferTimeout) * time.Second
	availableTools := make([]AvailableTool, 0, len(ctx.Tools))
	for _, t := range ctx.Tools {
		schema := t.InputSchema
		if len(schema) == 0 {
			schema = t.Parameters // OpenAI format
		}
		availableTools = append(availableTools, AvailableTool{
			Name:        t.Name,
			InputSchema: schema,
		})
	}
	buffer := NewBufferedSSEWriter(ctx.Writer,
		SSEBufferConfig{MaxEvents: secCfg.MaxBufferEvents, Timeout: timeout},
		SSERequestContext{TraceID: ctx.TraceID, SessionID: ctx.SessionID, Model: ctx.Model, APIType: ctx.APIType, Tools: availableTools},
	)

	// Get interceptor early to avoid goto issues.
	interceptor := security.GetGlobalInterceptor()

	// Read and buffer SSE events. Headers are NOT written to the client yet.
	bufferOverflowed := false
	reader := &bytes.Buffer{}
	buf := make([]byte, 4096)

readLoop:
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			reader.Write(buf[:n])

			// Process complete SSE events.
			for {
				data := reader.Bytes()
				idx := bytes.Index(data, []byte("\n\n"))
				if idx == -1 {
					idx = bytes.Index(data, []byte("\r\n\r\n"))
					if idx == -1 {
						break
					}
					eventData := data[:idx]
					raw := data[:idx+4]
					eventType, jsonData := parseSSEEventData(eventData)
					if err := buffer.BufferEvent(eventType, jsonData, raw); err != nil {
						log.Warn("[BUFFERED] %v — falling back to non-streaming retry", err)
						if _, drainErr := io.Copy(io.Discard, resp.Body); drainErr != nil {
							log.Debug("Failed to drain upstream response: %v", drainErr)
						}
						bufferOverflowed = true
						break readLoop
					}
					reader.Reset()
					reader.Write(data[idx+4:])
					continue
				}
				eventData := data[:idx]
				raw := data[:idx+2]
				eventType, jsonData := parseSSEEventData(eventData)
				if err := buffer.BufferEvent(eventType, jsonData, raw); err != nil {
					log.Warn("[BUFFERED] %v — falling back to non-streaming retry", err)
					if _, drainErr := io.Copy(io.Discard, resp.Body); drainErr != nil {
						log.Debug("Failed to drain upstream response: %v", drainErr)
					}
					bufferOverflowed = true
					break readLoop
				}
				reader.Reset()
				reader.Write(data[idx+2:])
			}
		}

		if readErr != nil {
			if readErr != io.EOF {
				log.Error("Read error: %v", readErr)
			}
			break
		}
	}

	// Buffer overflow: retry the same request with stream=false.
	// Because we haven't written any headers yet, the client still sees a normal response.
	if bufferOverflowed {
		responseBody, inputTokens, outputTokens, toolCalls, statusCode := p.retryAsNonStreaming(ctx)
		duration := time.Since(ctx.StartTime)
		log.Info("%s %s model=%s → %s status=%d duration=%v tokens=%d/%d tools=%d [stream→non-stream fallback]",
			ctx.Request.Method, ctx.Request.URL.Path, ctx.Model, ctx.TargetURL, statusCode, duration, inputTokens, outputTokens, len(toolCalls))
		if ctx.Provider != nil && ctx.Provider.IsEnabled() && ctx.SpanCtx != nil {
			ctx.Provider.EndLLMSpan(ctx.SpanCtx, telemetry.LLMSpanData{
				TraceID:      ctx.TraceID,
				SessionID:    ctx.SessionID,
				SpanKind:     ctx.SpanKind,
				SpanName:     ctx.SpanName,
				Model:        ctx.Model,
				TargetURL:    ctx.TargetURL,
				Messages:     ctx.RequestBody,
				Response:     responseBody,
				ToolCalls:    toolCalls,
				InputTokens:  inputTokens,
				OutputTokens: outputTokens,
				Latency:      duration,
				StatusCode:   statusCode,
				IsStreaming:  false,
			})
		}
		return
	}

	// Buffer complete: handle trailing unterminated event, then write headers and flush.
	if reader.Len() > 0 {
		remaining := bytes.TrimRight(reader.Bytes(), "\r\n")
		if len(remaining) > 0 {
			eventType, jsonData := parseSSEEventData(remaining)
			raw := reader.Bytes()
			if !bytes.HasSuffix(raw, []byte("\n\n")) {
				raw = append(raw, '\n', '\n')
			}
			if err := buffer.BufferEvent(eventType, jsonData, raw); err != nil {
				log.Debug("Failed to buffer trailing event: %v", err)
			} else {
				log.Debug("Buffered trailing SSE event: %s", eventType)
			}
		}
	}

	// Now safe to commit headers to the client and stream evaluated events.
	copyHeaders(ctx.Writer.Header(), savedHeaders)
	ctx.Writer.WriteHeader(savedStatus)
	if err := buffer.FlushModified(interceptor, secCfg.BlockMode); err != nil {
		log.Error("Flush error: %v", err)
	}

	// Log telemetry.
	duration := time.Since(ctx.StartTime)
	toolCalls := buffer.GetToolCalls()
	log.Info("%s %s model=%s → %s status=%d duration=%v tools=%d [buffered-stream]",
		ctx.Request.Method, ctx.Request.URL.Path, ctx.Model, ctx.TargetURL, savedStatus, duration, len(toolCalls))
	if ctx.Provider != nil && ctx.Provider.IsEnabled() && ctx.SpanCtx != nil {
		ctx.Provider.EndLLMSpan(ctx.SpanCtx, telemetry.LLMSpanData{
			TraceID:     ctx.TraceID,
			SessionID:   ctx.SessionID,
			SpanKind:    ctx.SpanKind,
			SpanName:    ctx.SpanName,
			Model:       ctx.Model,
			TargetURL:   ctx.TargetURL,
			Messages:    ctx.RequestBody,
			ToolCalls:   toolCalls,
			Latency:     duration,
			StatusCode:  savedStatus,
			IsStreaming: true,
		})
	}
}

// retryAsNonStreaming reissues the request with stream=false and writes the evaluated
// response directly to the client. Used as fallback when the SSE buffer overflows.
func (p *Proxy) retryAsNonStreaming(ctx *RequestContext) (responseBody json.RawMessage, inputTokens, outputTokens int64, toolCalls []telemetry.ToolCall, statusCode int) {
	log.Warn("[BUFFERED] Retrying as non-streaming for full security evaluation")

	nonStreamBody := forceNonStreaming(ctx.RequestBody)
	// Use a detached context so the retry is not canceled if the client
	// disconnects mid-stream. The retry must complete for security evaluation
	// regardless of the original request's lifecycle.
	retryCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	retryReq := ctx.UpstreamReq.Clone(retryCtx)
	retryReq.Body = io.NopCloser(bytes.NewReader(nonStreamBody))
	retryReq.ContentLength = int64(len(nonStreamBody))
	retryReq.Header.Del("Content-Encoding") // body is now uncompressed JSON

	resp, err := p.doRequest(retryReq)
	if err != nil {
		log.Error("Non-streaming retry failed: %v", err)
		http.Error(ctx.Writer, "Bad Gateway", http.StatusBadGateway)
		return nil, 0, 0, nil, http.StatusBadGateway
	}
	defer resp.Body.Close()

	statusCode = resp.StatusCode
	var rawBody []byte
	rawBody, inputTokens, outputTokens, toolCalls = processNonStreamingResponse(resp, ctx.APIType, ctx.TraceID, ctx.SessionID, ctx.Model)
	responseBody = rawBody

	copyHeaders(ctx.Writer.Header(), resp.Header)
	ctx.Writer.Header().Set("Content-Length", strconv.Itoa(len(rawBody)))
	ctx.Writer.WriteHeader(statusCode)
	writeBody(ctx.Writer, rawBody)
	return
}

// forceNonStreaming returns a copy of the JSON body with "stream" set to false.
// Preserves all other fields byte-for-byte via json.RawMessage.
// Uses SetEscapeHTML(false) so characters like & < > are not mangled.
func forceNonStreaming(body []byte) []byte {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil || raw == nil {
		return body // best-effort: return unchanged on parse failure or JSON null
	}
	raw["stream"] = json.RawMessage("false")
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(raw); err != nil {
		return body
	}
	b := buf.Bytes()
	return b[:len(b)-1] // strip trailing newline added by json.Encoder
}
