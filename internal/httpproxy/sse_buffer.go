package httpproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/BakeLens/crust/internal/eventlog"
	"github.com/BakeLens/crust/internal/message"
	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/security"
	"github.com/BakeLens/crust/internal/shellutil"
	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/types"
)

// bufferState tracks the lifecycle of a BufferedSSEWriter.
type bufferState int

const (
	bufferStateActive    bufferState = iota // zero value; buffering in progress
	bufferStateCompleted                    // FlushAll or FlushModified called
	bufferStateTimedOut                     // timeout exceeded; buffer rejected
)

// SSE event type strings for Anthropic and OpenAI Responses APIs.
const (
	// Anthropic streaming event types.
	sseContentBlockStart = "content_block_start"
	sseContentBlockDelta = "content_block_delta"
	sseContentBlockStop  = "content_block_stop"
	sseMessageStop       = "message_stop"

	// OpenAI Responses API streaming event types.
	sseResponseOutputItemAdded            = "response.output_item.added"
	sseResponseFunctionCallArgumentsDelta = "response.function_call_arguments.delta"
	sseResponseFunctionCallArgumentsDone  = "response.function_call_arguments.done"
	sseResponseOutputItemDone             = "response.output_item.done"
	sseResponseCompleted                  = "response.completed"
	sseResponseOutputTextDelta            = "response.output_text.delta"
)

// SSEEvent represents a buffered SSE event
type SSEEvent struct {
	EventType string // "message_start", "content_block_start", etc.
	Data      []byte
	Raw       []byte // Original raw bytes including "data: " prefix
}

// AvailableTool represents a tool available in the request
type AvailableTool struct {
	Name        string
	InputSchema json.RawMessage // The full schema for input validation
}

// SSEBufferConfig controls buffering behavior.
type SSEBufferConfig struct {
	MaxEvents int
	Timeout   time.Duration
}

// SSERequestContext holds per-request metadata used for security evaluation.
type SSERequestContext struct {
	TraceID   types.TraceID
	SessionID types.SessionID
	Model     string
	APIType   types.APIType
	Tools     []AvailableTool
}

// BufferedSSEWriter buffers SSE events for security evaluation before sending to client
type BufferedSSEWriter struct {
	underlying http.ResponseWriter
	flusher    http.Flusher
	parser     *SSEParser

	mu            sync.Mutex
	events        []SSEEvent
	toolCalls     map[int]*StreamingToolCall
	contentBuffer bytes.Buffer

	// Configuration
	maxBufferEvents int
	timeout         time.Duration

	// Metadata for security evaluation
	traceID   types.TraceID
	sessionID types.SessionID
	model     string
	apiType   types.APIType

	// Available tools from request (for replace mode)
	availableTools map[string]AvailableTool

	// State
	hasToolUse bool
	state      bufferState
	startTime  time.Time
}

// NewBufferedSSEWriter creates a buffered SSE writer
func NewBufferedSSEWriter(w http.ResponseWriter, cfg SSEBufferConfig, ctx SSERequestContext) *BufferedSSEWriter {
	flusher, _ := w.(http.Flusher)

	// Build tool lookup map
	toolMap := make(map[string]AvailableTool)
	for _, t := range ctx.Tools {
		toolMap[t.Name] = t
	}

	return &BufferedSSEWriter{
		underlying:      w,
		flusher:         flusher,
		parser:          NewSSEParser(true), // Enable sanitization
		events:          make([]SSEEvent, 0, 100),
		toolCalls:       make(map[int]*StreamingToolCall),
		maxBufferEvents: cfg.MaxEvents,
		timeout:         cfg.Timeout,
		traceID:         ctx.TraceID,
		sessionID:       ctx.SessionID,
		model:           ctx.Model,
		apiType:         ctx.APIType,
		availableTools:  toolMap,
		startTime:       time.Now(),
	}
}

// shellToolNames lists tool names that can execute shell commands (in priority order)
var shellToolNames = []string{"Bash", "bash", "Shell", "shell", "Execute", "execute", "Exec", "exec", "RunCommand", "run_command", "Terminal", "terminal", "Cmd", "cmd"}

// buildBlockedReplacement constructs the replacement command input for a blocked tool call.
func buildBlockedReplacement(toolName string, matchResult rules.MatchResult) map[string]string {
	msg := message.FormatReplaceInline(toolName, matchResult)
	cmd, err := shellutil.Command("echo", msg)
	if err != nil {
		cmd = "echo '[Crust] Tool blocked.'"
	}
	return map[string]string{
		"command":     cmd,
		"description": "Security: blocked tool call",
	}
}

// findShellTool finds a shell/command execution tool from available tools
// Returns the tool name and whether one was found
func (b *BufferedSSEWriter) findShellTool() (string, bool) {
	for _, name := range shellToolNames {
		if _, exists := b.availableTools[name]; exists {
			return name, true
		}
	}
	return "", false
}

// BufferEvent adds an SSE event to the buffer
func (b *BufferedSSEWriter) BufferEvent(eventType string, data, raw []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.state != bufferStateActive {
		return errors.New("buffer already completed")
	}

	// Check timeout
	if time.Since(b.startTime) > b.timeout {
		b.state = bufferStateTimedOut
		return errors.New("buffer timeout exceeded")
	}

	// Check size limit
	if len(b.events) >= b.maxBufferEvents {
		return errors.New("buffer size limit exceeded")
	}

	event := SSEEvent{
		EventType: eventType,
		Data:      bytes.Clone(data),
		Raw:       bytes.Clone(raw),
	}

	b.events = append(b.events, event)

	// Parse the event to extract tool calls
	b.parseEvent(eventType, data)

	return nil
}

// parseEvent extracts tool call information from SSE events using the unified parser
func (b *BufferedSSEWriter) parseEvent(eventType string, data []byte) {
	result := b.parser.ParseEvent(eventType, data, b.apiType)

	// Apply text content
	if result.TextContent != "" {
		b.contentBuffer.WriteString(result.TextContent)
	}

	// Apply tool call updates
	if b.parser.ApplyResultToToolCalls(result, b.toolCalls) {
		b.hasToolUse = true
	}

	// Also mark hasToolUse if we got a tool call delta for an existing tool
	if result.ToolCallDelta != nil {
		b.hasToolUse = true
	}
}

// GetToolCalls returns the parsed tool calls
func (b *BufferedSSEWriter) GetToolCalls() []telemetry.ToolCall {
	b.mu.Lock()
	defer b.mu.Unlock()

	var toolCalls []telemetry.ToolCall
	for _, tc := range b.toolCalls {
		if tc.Name == "" {
			continue // skip incomplete/malformed tool calls
		}
		toolCalls = append(toolCalls, telemetry.ToolCall{
			ID:        tc.ID,
			Name:      tc.Name,
			Arguments: json.RawMessage(bytes.Clone(tc.Arguments.Bytes())),
		})
	}
	return toolCalls
}

// FlushAll sends all buffered events to the client without modification
func (b *BufferedSSEWriter) FlushAll() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.state != bufferStateActive {
		return nil
	}
	b.state = bufferStateCompleted

	for _, event := range b.events {
		if err := b.writeRaw(event.Raw); err != nil {
			return err
		}
	}

	return nil
}

// FlushModified evaluates tool calls and sends modified response if needed
// blockMode: types.BlockModeRemove (delete tool calls) or types.BlockModeReplace (substitute with echo command)
func (b *BufferedSSEWriter) FlushModified(interceptor *security.Interceptor, blockMode types.BlockMode) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.state != bufferStateActive {
		return nil
	}
	b.state = bufferStateCompleted

	if !b.hasToolUse || interceptor == nil || !interceptor.IsEnabled() {
		// No tool use or no interceptor, flush as-is
		return b.flushEventsUnlocked()
	}

	// Evaluate each tool call
	engine := interceptor.GetEngine()

	// Based on global blockMode, all blocked calls go to either blockedIndices or replacedIndices
	blockedIndices := make(map[int]rules.MatchResult)  // for "remove" mode
	replacedIndices := make(map[int]rules.MatchResult) // for "replace" mode
	var blockedCalls []security.BlockedToolCall

	useReplaceMode := blockMode.IsReplace()

	for idx, tc := range b.toolCalls {
		matchResult := engine.Evaluate(rules.ToolCall{
			Name:      tc.Name,
			Arguments: json.RawMessage(tc.Arguments.Bytes()),
		})

		isBlocked := matchResult.Matched && matchResult.Action == rules.ActionBlock
		ruleName := ""

		if isBlocked {
			ruleName = matchResult.RuleName
			blockedCalls = append(blockedCalls, security.BlockedToolCall{
				ToolCall: telemetry.ToolCall{
					ID:        tc.ID,
					Name:      tc.Name,
					Arguments: json.RawMessage(tc.Arguments.Bytes()),
				},
				MatchResult: matchResult,
			})

			// Route to remove or replace based on global block mode
			if useReplaceMode {
				replacedIndices[idx] = matchResult
				log.Warn("[BUFFERED] Replaced tool call: %s (rule: %s)", tc.Name, matchResult.RuleName)
			} else {
				blockedIndices[idx] = matchResult
				log.Warn("[BUFFERED] Blocked tool call: %s (rule: %s)", tc.Name, matchResult.RuleName)
			}
		}

		eventlog.Record(eventlog.Event{
			Layer:      eventlog.LayerProxyBuffer,
			TraceID:    b.traceID,
			SessionID:  b.sessionID,
			ToolName:   tc.Name,
			Arguments:  json.RawMessage(tc.Arguments.Bytes()),
			APIType:    b.apiType,
			Model:      b.model,
			WasBlocked: isBlocked,
			RuleName:   ruleName,
		})
	}

	if len(blockedIndices) == 0 && len(replacedIndices) == 0 {
		// No blocked/replaced calls, flush as-is
		return b.flushEventsUnlocked()
	}

	// Generate modified stream
	return b.flushFilteredEvents(blockedIndices, replacedIndices, blockedCalls)
}

func (b *BufferedSSEWriter) flushEventsUnlocked() error {
	for _, event := range b.events {
		if err := b.writeRaw(event.Raw); err != nil {
			return err
		}
	}
	return nil
}

// flushFilteredEvents sends events but filters out blocked tool use content blocks
// blockedIndices: tool calls to remove entirely
// replacedIndices: tool calls to replace with safe echo command
func (b *BufferedSSEWriter) flushFilteredEvents(blockedIndices, replacedIndices map[int]rules.MatchResult, blockedCalls []security.BlockedToolCall) error {
	switch b.apiType {
	case types.APITypeAnthropic:
		return b.flushFilteredAnthropicEvents(blockedIndices, replacedIndices, blockedCalls)
	case types.APITypeOpenAICompletion:
		return b.flushFilteredOpenAIEvents(blockedIndices, replacedIndices, blockedCalls)
	case types.APITypeOpenAIResponses:
		return b.flushFilteredOpenAIResponsesEvents(blockedIndices, replacedIndices, blockedCalls)
	case types.APITypeUnknown:
		return b.flushEventsUnlocked()
	default:
		return fmt.Errorf("unhandled API type: %s", b.apiType)
	}
}

func (b *BufferedSSEWriter) flushFilteredAnthropicEvents(blockedIndices, replacedIndices map[int]rules.MatchResult, blockedCalls []security.BlockedToolCall) error {
	// Track which content block indices to skip (block action)
	skipIndices := make(map[int]bool)
	for idx := range blockedIndices {
		skipIndices[idx] = true
	}

	// Track which content block indices to replace
	replaceIndices := make(map[int]bool)
	for idx := range replacedIndices {
		replaceIndices[idx] = true
	}

	warningInjected := false
	replacedStartSent := make(map[int]bool) // Track if we already sent the replacement content_block_start
	replacedDeltaSent := make(map[int]bool) // Track if we already sent the replacement delta

	for _, event := range b.events {
		// Check if this event is related to a blocked/replaced content block
		shouldSkip := false
		shouldReplace := false
		eventIndex := -1

		if bytes.Contains(event.Data, []byte(`"`+sseContentBlockStart+`"`)) {
			var evt AnthropicContentBlockStart
			if err := json.Unmarshal(event.Data, &evt); err == nil {
				eventIndex = evt.Index
				if skipIndices[evt.Index] {
					shouldSkip = true
				} else if replaceIndices[evt.Index] {
					shouldReplace = true
				}
			}
		} else if bytes.Contains(event.Data, []byte(`"`+sseContentBlockDelta+`"`)) {
			var evt AnthropicContentBlockDelta
			if err := json.Unmarshal(event.Data, &evt); err == nil {
				eventIndex = evt.Index
				if skipIndices[evt.Index] {
					shouldSkip = true
				} else if replaceIndices[evt.Index] {
					shouldReplace = true
				}
			}
		} else if bytes.Contains(event.Data, []byte(`"`+sseContentBlockStop+`"`)) {
			var evt AnthropicContentBlockStop
			if err := json.Unmarshal(event.Data, &evt); err == nil {
				eventIndex = evt.Index
				if skipIndices[evt.Index] {
					shouldSkip = true
				} else if replaceIndices[evt.Index] {
					// For content_block_stop, just send as-is (no modification needed)
					shouldReplace = false
				}
			}
		}

		if shouldSkip {
			continue
		}

		if shouldReplace && eventIndex >= 0 {
			matchResult := replacedIndices[eventIndex]
			tc := b.toolCalls[eventIndex]
			if tc == nil {
				continue
			}

			// Find a shell tool (Bash, shell, execute, etc.)
			shellToolName, hasShellTool := b.findShellTool()

			// If no shell tool available, fall back to remove mode (skip this event)
			if !hasShellTool {
				log.Warn("[BUFFERED] Replace mode: no shell tool available, falling back to remove for tool '%s'", tc.Name)
				continue
			}

			// Handle content_block_start
			if bytes.Contains(event.Data, []byte(`"`+sseContentBlockStart+`"`)) && !replacedStartSent[eventIndex] {
				replacedStartSent[eventIndex] = true
				if err := b.writeSSEEvent(sseContentBlockStart, map[string]any{
					"type":  sseContentBlockStart,
					"index": eventIndex,
					"content_block": map[string]any{
						"type": "tool_use", "id": tc.ID, "name": shellToolName, "input": map[string]any{},
					},
				}); err != nil {
					return err
				}
				continue
			}

			// Handle content_block_delta
			if bytes.Contains(event.Data, []byte(`"`+sseContentBlockDelta+`"`)) && !replacedDeltaSent[eventIndex] {
				replacedDeltaSent[eventIndex] = true
				input := buildBlockedReplacement(tc.Name, matchResult)
				inputJSONBytes, err := marshalJSON(input)
				if err != nil {
					continue
				}
				if err := b.writeSSEEvent(sseContentBlockDelta, map[string]any{
					"type":  sseContentBlockDelta,
					"index": eventIndex,
					"delta": map[string]any{
						"type":         "input_json_delta",
						"partial_json": string(inputJSONBytes),
					},
				}); err != nil {
					return err
				}
				continue
			}

			// Skip subsequent deltas for the same replaced block
			if bytes.Contains(event.Data, []byte(`"`+sseContentBlockDelta+`"`)) {
				continue
			}
		}

		// Inject warning before message_stop (for both remove and replace modes if not already sent via text block)
		if !warningInjected && bytes.Contains(event.Data, []byte(`"`+sseMessageStop+`"`)) {
			// Only inject for remove mode; replace mode already has text blocks
			if len(blockedIndices) > 0 {
				if err := b.injectWarning(blockedCalls); err != nil {
					log.Warn("Failed to inject warning: %v", err)
				}
			}
			warningInjected = true
		}

		if err := b.writeRaw(event.Raw); err != nil {
			return err
		}
	}

	return nil
}

// injectWarning injects a security warning into the SSE stream in the appropriate format.
func (b *BufferedSSEWriter) injectWarning(blockedCalls []security.BlockedToolCall) error {
	switch b.apiType {
	case types.APITypeAnthropic:
		return b.injectAnthropicWarning(blockedCalls)
	case types.APITypeOpenAICompletion:
		return b.injectOpenAIWarning(blockedCalls)
	case types.APITypeOpenAIResponses:
		return b.injectOpenAIResponsesWarning(blockedCalls)
	case types.APITypeUnknown:
		return nil
	default:
		return fmt.Errorf("unhandled API type: %s", b.apiType)
	}
}

func (b *BufferedSSEWriter) injectAnthropicWarning(blockedCalls []security.BlockedToolCall) error {
	warning := security.BuildWarningContent(blockedCalls)

	if err := b.writeSSEEvent(sseContentBlockStart, map[string]any{
		"type":          sseContentBlockStart,
		"index":         WarningBlockIndex,
		"content_block": map[string]any{"type": "text", "text": ""},
	}); err != nil {
		return err
	}
	if err := b.writeSSEEvent(sseContentBlockDelta, map[string]any{
		"type":  sseContentBlockDelta,
		"index": WarningBlockIndex,
		"delta": map[string]any{"type": "text_delta", "text": warning},
	}); err != nil {
		return err
	}
	return b.writeSSEEvent(sseContentBlockStop, map[string]any{
		"type":  sseContentBlockStop,
		"index": WarningBlockIndex,
	})
}

func (b *BufferedSSEWriter) flushFilteredOpenAIEvents(blockedIndices, replacedIndices map[int]rules.MatchResult, blockedCalls []security.BlockedToolCall) error {
	// For OpenAI, we need to rewrite the chunks to exclude/replace blocked tool calls
	warningInjected := false

	// For replace mode: track which tool call indices have already received
	// their replacement echo command so we only emit it once.
	replacedArgsSent := make(map[int]bool)
	shellToolName, hasShellTool := b.findShellTool()

	for _, event := range b.events {
		// Check for [DONE] marker
		if bytes.Equal(bytes.TrimSpace(event.Data), []byte("[DONE]")) {
			// Inject warning before [DONE] for remove mode
			if !warningInjected && len(blockedIndices) > 0 {
				if err := b.injectWarning(blockedCalls); err != nil {
					log.Warn("Failed to inject warning: %v", err)
				}
				warningInjected = true
			}
			if err := b.writeRaw(event.Raw); err != nil {
				return err
			}
			continue
		}

		var chunk OpenAIStreamChunk
		if err := json.Unmarshal(event.Data, &chunk); err != nil {
			// Not a valid chunk, send as-is
			if err := b.writeRaw(event.Raw); err != nil {
				return err
			}
			continue
		}

		// Filter out blocked tool calls and replace marked ones
		modified := false
		for choiceIdx := range chunk.Choices {
			choice := &chunk.Choices[choiceIdx]
			if len(choice.Delta.ToolCalls) == 0 {
				continue
			}

			// Use same type as original ToolCalls
			type toolCallDelta struct {
				Index    int    `json:"index"`
				ID       string `json:"id,omitempty"`
				Function struct {
					Name      string `json:"name,omitempty"`
					Arguments string `json:"arguments,omitempty"`
				} `json:"function"`
			}
			filtered := make([]toolCallDelta, 0)

			for _, tc := range choice.Delta.ToolCalls {
				if blockedIndices[tc.Index].Matched {
					// Remove mode: skip blocked tool calls entirely
					modified = true
					continue
				}

				if replacedIndices[tc.Index].Matched {
					modified = true

					// Replace mode: substitute with safe shell echo command.
					// If no shell tool available, fall back to remove mode.
					if !hasShellTool {
						if origTC, ok := b.toolCalls[tc.Index]; ok {
							log.Warn("[BUFFERED] Replace mode: no shell tool available, falling back to remove for tool '%s'", origTC.Name)
						}
						continue
					}

					replaced := toolCallDelta{Index: tc.Index}

					if tc.ID != "" {
						// First delta for this tool call — rewrite name to shell tool
						replaced.ID = tc.ID
						replaced.Function.Name = shellToolName
					}

					if !replacedArgsSent[tc.Index] {
						// Emit the replacement arguments exactly once
						replacedArgsSent[tc.Index] = true
						matchResult := replacedIndices[tc.Index]
						origName := ""
						if origTC, ok := b.toolCalls[tc.Index]; ok {
							origName = origTC.Name
						}
						input := buildBlockedReplacement(origName, matchResult)
						argBytes, err := marshalJSON(input)
						if err == nil {
							replaced.Function.Arguments = string(argBytes)
						}
					}
					// Subsequent argument deltas for this index are dropped (we sent full args above)

					filtered = append(filtered, replaced)
					continue
				}

				// Keep unmatched tool calls - convert to local type
				kept := toolCallDelta{
					Index: tc.Index,
					ID:    tc.ID,
				}
				kept.Function.Name = tc.Function.Name
				kept.Function.Arguments = tc.Function.Arguments
				filtered = append(filtered, kept)
			}

			// Need to convert back - just modify in place via JSON marshal/unmarshal dance
			if modified {
				filteredJSON, err := marshalJSON(filtered)
				if err != nil {
					log.Debug("Failed to marshal filtered tool calls: %v", err)
					continue
				}
				if err := json.Unmarshal(filteredJSON, &choice.Delta.ToolCalls); err != nil {
					log.Debug("Failed to unmarshal filtered tool calls: %v", err)
				}
			}
		}

		if modified {
			if err := b.writeSSEData(chunk); err != nil {
				return err
			}
		} else {
			if err := b.writeRaw(event.Raw); err != nil {
				return err
			}
		}
	}

	return nil
}

func (b *BufferedSSEWriter) injectOpenAIWarning(blockedCalls []security.BlockedToolCall) error {
	warning := security.BuildWarningContent(blockedCalls)
	return b.writeSSEData(map[string]any{
		"id":      "security-warning",
		"object":  "chat.completion.chunk",
		"created": time.Now().Unix(),
		"model":   b.model,
		"choices": []map[string]any{{
			"index":         0,
			"delta":         map[string]any{"content": warning},
			"finish_reason": nil,
		}},
	})
}

func (b *BufferedSSEWriter) flushFilteredOpenAIResponsesEvents(blockedIndices, replacedIndices map[int]rules.MatchResult, blockedCalls []security.BlockedToolCall) error {
	// Track which output_index values to skip entirely (remove mode)
	skipIndices := make(map[int]bool)
	for idx := range blockedIndices {
		skipIndices[idx] = true
	}

	// Track which output_index values to replace with echo command
	replaceIndices := make(map[int]bool)
	for idx := range replacedIndices {
		replaceIndices[idx] = true
	}

	warningInjected := false
	replacedItemSent := make(map[int]bool) // Track if replacement output_item.added was sent
	replacedArgsSent := make(map[int]bool) // Track if replacement arguments delta was sent
	shellToolName, hasShellTool := b.findShellTool()

	for _, event := range b.events {
		// Check output_index in the event JSON. Use a pointer so we can
		// distinguish "field absent" (nil) from "field present with value 0".
		var indexProbe struct {
			OutputIndex *int `json:"output_index"`
		}
		json.Unmarshal(event.Data, &indexProbe) //nolint:errcheck // best-effort probe

		// Determine action for this event
		shouldSkip := false
		shouldReplace := false
		if indexProbe.OutputIndex != nil {
			idx := *indexProbe.OutputIndex
			if skipIndices[idx] {
				shouldSkip = true
			} else if replaceIndices[idx] {
				shouldReplace = true
			}
		}

		if shouldSkip {
			continue
		}

		if shouldReplace {
			outputIdx := *indexProbe.OutputIndex

			// If no shell tool available, fall back to remove mode (skip)
			if !hasShellTool {
				if tc := b.toolCalls[outputIdx]; tc != nil {
					log.Warn("[BUFFERED] Replace mode: no shell tool available, falling back to remove for tool '%s'", tc.Name)
				}
				continue
			}

			switch event.EventType {
			case sseResponseOutputItemAdded:
				if !replacedItemSent[outputIdx] {
					replacedItemSent[outputIdx] = true
					tc := b.toolCalls[outputIdx]
					if tc == nil {
						continue
					}
					// Emit replacement output_item.added with shell tool name
					replacedEvent := map[string]any{
						"type":         sseResponseOutputItemAdded,
						"output_index": outputIdx,
						"item": map[string]any{
							"type":    "function_call",
							"call_id": tc.ID,
							"name":    shellToolName,
							"id":      tc.ID,
						},
					}
					if err := b.writeSSEEvent(event.EventType, replacedEvent); err != nil {
						return err
					}
				}
				continue

			case sseResponseFunctionCallArgumentsDelta:
				if !replacedArgsSent[outputIdx] {
					replacedArgsSent[outputIdx] = true
					tc := b.toolCalls[outputIdx]
					if tc == nil {
						continue
					}
					matchResult := replacedIndices[outputIdx]
					input := buildBlockedReplacement(tc.Name, matchResult)
					argBytes, err := marshalJSON(input)
					if err != nil {
						continue
					}
					// Emit single delta with full replacement arguments
					replacedEvent := map[string]any{
						"type":         sseResponseFunctionCallArgumentsDelta,
						"output_index": outputIdx,
						"delta":        string(argBytes),
					}
					if err := b.writeSSEEvent(event.EventType, replacedEvent); err != nil {
						return err
					}
				}
				// Skip subsequent argument deltas
				continue

			case sseResponseFunctionCallArgumentsDone:
				// Emit done with the full replacement arguments
				tc := b.toolCalls[outputIdx]
				if tc == nil {
					continue
				}
				matchResult := replacedIndices[outputIdx]
				input := buildBlockedReplacement(tc.Name, matchResult)
				argBytes, err := marshalJSON(input)
				if err != nil {
					continue
				}
				replacedEvent := map[string]any{
					"type":         sseResponseFunctionCallArgumentsDone,
					"output_index": outputIdx,
					"arguments":    string(argBytes),
				}
				if err := b.writeSSEEvent(event.EventType, replacedEvent); err != nil {
					return err
				}
				continue

			case sseResponseOutputItemDone:
				// Emit done with the replaced item
				tc := b.toolCalls[outputIdx]
				if tc == nil {
					continue
				}
				matchResult := replacedIndices[outputIdx]
				input := buildBlockedReplacement(tc.Name, matchResult)
				argBytes, err := marshalJSON(input)
				if err != nil {
					continue
				}
				replacedEvent := map[string]any{
					"type":         sseResponseOutputItemDone,
					"output_index": outputIdx,
					"item": map[string]any{
						"type":      "function_call",
						"call_id":   tc.ID,
						"name":      shellToolName,
						"id":        tc.ID,
						"arguments": string(argBytes),
					},
				}
				if err := b.writeSSEEvent(event.EventType, replacedEvent); err != nil {
					return err
				}
				continue

			default:
				// Skip any other events for this output_index
				continue
			}
		}

		// Inject warning before response.completed (for remove mode)
		if !warningInjected && event.EventType == sseResponseCompleted {
			if len(blockedIndices) > 0 {
				if err := b.injectWarning(blockedCalls); err != nil {
					log.Warn("Failed to inject Responses API warning: %v", err)
				}
			}
			warningInjected = true
		}

		if err := b.writeRaw(event.Raw); err != nil {
			return err
		}
	}

	return nil
}

// marshalJSON encodes v to JSON without HTML escaping (&, <, > are preserved).
// json.Marshal HTML-escapes these by default, which corrupts user content.
func marshalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	b := buf.Bytes()
	return b[:len(b)-1], nil // strip trailing newline from json.Encoder
}

// writeSSEEvent marshals data as JSON and writes it as an SSE event with "event: <type>\ndata: ...\n\n" framing.
func (b *BufferedSSEWriter) writeSSEEvent(eventType string, data any) error {
	jsonData, err := marshalJSON(data)
	if err != nil {
		log.Warn("Failed to marshal SSE event: %v", err)
		return err
	}
	formatted := fmt.Sprintf("event: %s\ndata: %s\n\n", eventType, jsonData)
	if _, err := b.underlying.Write([]byte(formatted)); err != nil {
		return err
	}
	if b.flusher != nil {
		b.flusher.Flush()
	}
	return nil
}

// writeSSEData writes an SSE event with "data: ...\n\n" framing (no event type line).
func (b *BufferedSSEWriter) writeSSEData(data any) error {
	jsonData, err := marshalJSON(data)
	if err != nil {
		log.Warn("Failed to marshal SSE data: %v", err)
		return err
	}
	formatted := fmt.Sprintf("data: %s\n\n", jsonData)
	if _, err := b.underlying.Write([]byte(formatted)); err != nil {
		return err
	}
	if b.flusher != nil {
		b.flusher.Flush()
	}
	return nil
}

// writeRaw writes pre-formatted bytes and flushes.
func (b *BufferedSSEWriter) writeRaw(raw []byte) error {
	if _, err := b.underlying.Write(raw); err != nil {
		return err
	}
	if b.flusher != nil {
		b.flusher.Flush()
	}
	return nil
}

func (b *BufferedSSEWriter) injectOpenAIResponsesWarning(blockedCalls []security.BlockedToolCall) error {
	warning := security.BuildWarningContent(blockedCalls)
	return b.writeSSEEvent(sseResponseOutputTextDelta, map[string]any{
		"type":          sseResponseOutputTextDelta,
		"output_index":  WarningBlockIndex,
		"content_index": 0,
		"delta":         warning,
	})
}
