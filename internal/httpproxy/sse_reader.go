package httpproxy

import (
	"bytes"
	"encoding/json"
	"io"
	"sync"

	"github.com/BakeLens/crust/internal/eventlog"
	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/security"
	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/types"
)

// SSEReader wraps a response body to extract token usage from SSE streams.
type SSEReader struct {
	reader  io.ReadCloser
	apiType types.APIType
	parser  *SSEParser

	buffer        bytes.Buffer
	contentBuffer bytes.Buffer

	mu           sync.Mutex
	inputTokens  int64
	outputTokens int64

	toolCalls    map[int]*StreamingToolCall
	toolCallsArr []telemetry.ToolCall

	onComplete func(input, output int64, content string, toolCalls []telemetry.ToolCall)
	completed  bool

	// Security interception fields
	traceID   types.TraceID
	sessionID types.SessionID
	model     string
}

// NewSSEReaderWithSecurity creates a new SSE reader with security interception support
func NewSSEReaderWithSecurity(body io.ReadCloser, apiType types.APIType, traceID types.TraceID, sessionID types.SessionID, model string, onComplete func(int64, int64, string, []telemetry.ToolCall)) *SSEReader {
	return &SSEReader{
		reader:     body,
		apiType:    apiType,
		parser:     NewSSEParser(true), // Enable sanitization
		onComplete: onComplete,
		toolCalls:  make(map[int]*StreamingToolCall),
		traceID:    traceID,
		sessionID:  sessionID,
		model:      model,
	}
}

func (r *SSEReader) Read(p []byte) (n int, err error) {
	n, err = r.reader.Read(p)
	if n > 0 {
		r.buffer.Write(p[:n])
		r.processBuffer()
	}

	if err == io.EOF {
		r.triggerComplete()
	}

	return n, err
}

func (r *SSEReader) Close() error {
	r.triggerComplete()
	return r.reader.Close()
}

func (r *SSEReader) triggerComplete() {
	r.mu.Lock()
	if r.completed || r.onComplete == nil {
		r.mu.Unlock()
		return
	}
	r.completed = true
	input, output := r.inputTokens, r.outputTokens
	content := r.contentBuffer.String()
	callback := r.onComplete

	r.finalizeToolCalls()
	toolCalls := r.toolCallsArr

	// Security interception for streaming responses
	// SECURITY LIMITATION: For SSE streaming, tool calls are evaluated AFTER being sent to the client.
	// This is an architectural limitation - the response is streamed in real-time.
	// Blocking is only possible for non-streaming responses.
	// For streaming: we log violations and emit warnings, but cannot prevent the tool call.
	// MITIGATION: Consider implementing response buffering for critical security rules,
	// or advise users to disable streaming for high-security use cases.
	interceptor := security.GetGlobalInterceptor()
	if interceptor != nil && interceptor.IsEnabled() && len(toolCalls) > 0 {
		engine := interceptor.GetEngine()

		// Log all tool calls and check for violations
		for _, tc := range toolCalls {
			matchResult := engine.Evaluate(rules.ToolCall{
				Name:      tc.Name,
				Arguments: tc.Arguments,
			})

			blocked := matchResult.Matched && matchResult.Action == rules.ActionBlock
			ruleName := ""
			if blocked {
				ruleName = matchResult.RuleName
				log.Warn("[STREAMING] Tool call would be blocked: %s (rule: %s) - already sent to client",
					tc.Name, matchResult.RuleName)
			}

			eventlog.Record(eventlog.Event{
				Layer:      eventlog.LayerProxyStream,
				TraceID:    r.traceID,
				SessionID:  r.sessionID,
				ToolName:   tc.Name,
				Arguments:  tc.Arguments,
				APIType:    r.apiType,
				Model:      r.model,
				WasBlocked: blocked,
				RuleName:   ruleName,
			})
		}
	}

	r.mu.Unlock()

	callback(input, output, content, toolCalls)
}

func (r *SSEReader) finalizeToolCalls() {
	for _, tc := range r.toolCalls {
		r.toolCallsArr = append(r.toolCallsArr, telemetry.ToolCall{
			ID:        tc.ID,
			Name:      tc.Name,
			Arguments: json.RawMessage(bytes.Clone(tc.Arguments.Bytes())),
		})
	}
}

func (r *SSEReader) processBuffer() {
	data := r.buffer.Bytes()

	for {
		idx := bytes.Index(data, []byte("\n\n"))
		if idx == -1 {
			idx = bytes.Index(data, []byte("\r\n\r\n"))
			if idx == -1 {
				break
			}
			r.parseSSEEvent(data[:idx])
			data = data[idx+4:]
			continue
		}

		r.parseSSEEvent(data[:idx])
		data = data[idx+2:]
	}

	r.buffer.Reset()
	r.buffer.Write(data)
}

func (r *SSEReader) parseSSEEvent(event []byte) {
	eventType, dataLine := parseSSEEventData(event)

	if len(dataLine) == 0 {
		return
	}

	if bytes.Equal(dataLine, []byte("[DONE]")) {
		return
	}

	// Use unified parser
	result := r.parser.ParseEvent(eventType, dataLine, r.apiType)

	r.mu.Lock()
	defer r.mu.Unlock()

	// Apply token usage
	if result.InputTokens > r.inputTokens {
		r.inputTokens = result.InputTokens
	}
	if result.OutputTokens > r.outputTokens {
		r.outputTokens = result.OutputTokens
	}

	// Apply text content
	if result.TextContent != "" {
		r.contentBuffer.WriteString(result.TextContent)
	}

	// Apply tool call updates
	r.parser.ApplyResultToToolCalls(result, r.toolCalls)
}

// Note: SSE event types (anthropicMessageStart, etc.) and parsing logic
// are now in sse_parser.go for shared use across SSEReader and BufferedSSEWriter.
