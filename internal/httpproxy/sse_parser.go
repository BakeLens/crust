// Package proxy provides SSE parsing for LLM streaming responses.
package httpproxy

import (
	"bytes"
	"encoding/json"

	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/types"
)

// API-specific protocol constants for content block and delta types.
const (
	contentTypeToolUse      = "tool_use"         // Anthropic
	contentTypeFunctionCall = "function_call"    // OpenAI Responses
	contentTypeComputerCall = "computer_call"    // OpenAI Responses (computer use)
	deltaTypeText           = "text_delta"       // Anthropic
	deltaTypeInputJSON      = "input_json_delta" // Anthropic
)

// StreamingToolCall represents a tool call being accumulated from SSE events.
// Used by both SSEReader and BufferedSSEWriter.
type StreamingToolCall struct {
	ID        string
	Name      string
	Arguments bytes.Buffer
}

// Anthropic SSE event structures

// AnthropicMessageStart represents the message_start event.
type AnthropicMessageStart struct {
	Type    string `json:"type"`
	Message struct {
		Usage struct {
			InputTokens  int64 `json:"input_tokens"`
			OutputTokens int64 `json:"output_tokens"`
		} `json:"usage"`
	} `json:"message"`
}

// AnthropicMessageDelta represents the message_delta event.
type AnthropicMessageDelta struct {
	Type  string `json:"type"`
	Usage struct {
		InputTokens  int64 `json:"input_tokens"`
		OutputTokens int64 `json:"output_tokens"`
	} `json:"usage"`
}

// AnthropicContentBlockStart represents the content_block_start event.
type AnthropicContentBlockStart struct {
	Type         string `json:"type"`
	Index        int    `json:"index"`
	ContentBlock struct {
		Type  string   `json:"type"`
		ID    string   `json:"id"`
		Name  string   `json:"name"`
		Input struct{} `json:"input"` // Always empty object at start
	} `json:"content_block"`
}

// AnthropicContentBlockDelta represents the content_block_delta event.
type AnthropicContentBlockDelta struct {
	Type  string `json:"type"`
	Index int    `json:"index"`
	Delta struct {
		Type        string `json:"type"`
		Text        string `json:"text"`
		PartialJSON string `json:"partial_json"`
	} `json:"delta"`
}

// AnthropicContentBlockStop represents the content_block_stop event.
type AnthropicContentBlockStop struct {
	Type  string `json:"type"`
	Index int    `json:"index"`
}

// OpenAI SSE event structures

// OpenAIStreamChunk represents a streaming chunk from OpenAI.
type OpenAIStreamChunk struct {
	Choices []OpenAIStreamChoice `json:"choices"`
	Usage   *OpenAIUsage         `json:"usage"`
}

// OpenAIStreamChoice represents a choice in a streaming chunk.
type OpenAIStreamChoice struct {
	Delta struct {
		Content   string                `json:"content"`
		ToolCalls []OpenAIToolCallDelta `json:"tool_calls"`
	} `json:"delta"`
}

// OpenAIToolCallDelta represents a partial tool call in a streaming chunk.
type OpenAIToolCallDelta struct {
	Index    int    `json:"index"`
	ID       string `json:"id"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// OpenAIUsage represents token usage from OpenAI.
type OpenAIUsage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

// OpenAI Responses API SSE event structures

// OpenAIResponsesOutputItemAdded represents the response.output_item.added event.
type OpenAIResponsesOutputItemAdded struct {
	Item struct {
		Type   string `json:"type"`    // "function_call"
		CallID string `json:"call_id"` // Tool call ID
		Name   string `json:"name"`    // Function name
		ID     string `json:"id"`      // Output item ID
		Index  int    `json:"index"`   // Output index (not present in all events, but included when available)
	} `json:"item"`
	OutputIndex int `json:"output_index"`
}

// OpenAIResponsesFunctionCallArgsDelta represents the response.function_call_arguments.delta event.
type OpenAIResponsesFunctionCallArgsDelta struct {
	Delta       string `json:"delta"`
	OutputIndex int    `json:"output_index"`
	ItemID      string `json:"item_id"`
}

// OpenAIResponsesOutputTextDelta represents the response.output_text.delta event.
type OpenAIResponsesOutputTextDelta struct {
	Delta       string `json:"delta"`
	OutputIndex int    `json:"output_index"`
}

// OpenAIResponsesCompleted represents the response.completed event.
type OpenAIResponsesCompleted struct {
	Response struct {
		Usage struct {
			InputTokens  int64 `json:"input_tokens"`
			OutputTokens int64 `json:"output_tokens"`
		} `json:"usage"`
	} `json:"response"`
}

// SSEParser provides unified SSE parsing with optional sanitization.
type SSEParser struct {
	sanitize bool
}

// NewSSEParser creates a new SSE parser.
// If sanitize is true, tool names will be sanitized using the rules sanitizer.
func NewSSEParser(sanitize bool) *SSEParser {
	return &SSEParser{sanitize: sanitize}
}

// ParseResult contains the result of parsing an SSE event.
type ParseResult struct {
	// Token usage (updated incrementally)
	InputTokens  int64
	OutputTokens int64

	// Content accumulation
	TextContent string

	// Tool call events
	ToolCallStart *ToolCallStartEvent
	ToolCallDelta *ToolCallDeltaEvent
}

// ToolCallStartEvent represents the start of a new tool call.
type ToolCallStartEvent struct {
	Index int
	ID    string
	Name  string
}

// ToolCallDeltaEvent represents incremental tool call data.
type ToolCallDeltaEvent struct {
	Index       int
	Text        string // For text content
	PartialJSON string // For tool call arguments
}

// ParseAnthropicEvent parses an Anthropic SSE event and returns the result.
func (p *SSEParser) ParseAnthropicEvent(data []byte) ParseResult {
	var result ParseResult

	if bytes.Contains(data, []byte(`"message_start"`)) {
		var event AnthropicMessageStart
		if err := json.Unmarshal(data, &event); err == nil {
			result.InputTokens = max(0, event.Message.Usage.InputTokens)
			result.OutputTokens = max(0, event.Message.Usage.OutputTokens)
		}
	} else if bytes.Contains(data, []byte(`"content_block_start"`)) {
		var event AnthropicContentBlockStart
		if err := json.Unmarshal(data, &event); err == nil {
			if event.ContentBlock.Type == contentTypeToolUse {
				name := event.ContentBlock.Name
				if p.sanitize {
					name = rules.SanitizeToolName(name)
				}
				result.ToolCallStart = &ToolCallStartEvent{
					Index: event.Index,
					ID:    event.ContentBlock.ID,
					Name:  name,
				}
			}
		}
	} else if bytes.Contains(data, []byte(`"content_block_delta"`)) {
		var event AnthropicContentBlockDelta
		if err := json.Unmarshal(data, &event); err == nil {
			if event.Delta.Type == deltaTypeText && event.Delta.Text != "" {
				result.TextContent = event.Delta.Text
			} else if event.Delta.Type == deltaTypeInputJSON && event.Delta.PartialJSON != "" {
				result.ToolCallDelta = &ToolCallDeltaEvent{
					Index:       event.Index,
					PartialJSON: event.Delta.PartialJSON,
				}
			}
		}
	} else if bytes.Contains(data, []byte(`"message_delta"`)) {
		var event AnthropicMessageDelta
		if err := json.Unmarshal(data, &event); err == nil {
			result.InputTokens = max(0, event.Usage.InputTokens)
			result.OutputTokens = max(0, event.Usage.OutputTokens)
		}
	}

	return result
}

// ParseOpenAIEvent parses an OpenAI SSE event and returns the result.
func (p *SSEParser) ParseOpenAIEvent(data []byte) ParseResult {
	var result ParseResult

	var chunk OpenAIStreamChunk
	if err := json.Unmarshal(data, &chunk); err != nil {
		return result
	}

	for _, choice := range chunk.Choices {
		if choice.Delta.Content != "" {
			result.TextContent = choice.Delta.Content
		}

		for _, tc := range choice.Delta.ToolCalls {
			// Tool call start (has ID and/or name)
			if tc.ID != "" || tc.Function.Name != "" {
				name := tc.Function.Name
				if p.sanitize && name != "" {
					name = rules.SanitizeToolName(name)
				}
				result.ToolCallStart = &ToolCallStartEvent{
					Index: tc.Index,
					ID:    tc.ID,
					Name:  name,
				}
			}

			// Tool call delta (has arguments)
			if tc.Function.Arguments != "" {
				result.ToolCallDelta = &ToolCallDeltaEvent{
					Index:       tc.Index,
					PartialJSON: tc.Function.Arguments,
				}
			}
		}
	}

	if chunk.Usage != nil {
		result.InputTokens = max(0, chunk.Usage.PromptTokens)
		result.OutputTokens = max(0, chunk.Usage.CompletionTokens)
	}

	return result
}

// ParseEvent parses an SSE event based on API type.
// eventType is the SSE "event:" field; used by the Responses API for dispatch.
// Anthropic and OpenAI Chat Completions callers may pass "" (they ignore it).
func (p *SSEParser) ParseEvent(eventType string, data []byte, apiType types.APIType) ParseResult {
	switch apiType {
	case types.APITypeAnthropic:
		return p.ParseAnthropicEvent(data)
	case types.APITypeOpenAICompletion:
		return p.ParseOpenAIEvent(data)
	case types.APITypeOpenAIResponses:
		return p.ParseOpenAIResponsesEvent(eventType, data)
	case types.APITypeUnknown:
		return ParseResult{}
	default:
		return ParseResult{} // unknown API type — treat as no-op
	}
}

// ParseOpenAIResponsesEvent parses an OpenAI Responses API SSE event.
// Dispatches on the eventType string (from the SSE "event:" line).
func (p *SSEParser) ParseOpenAIResponsesEvent(eventType string, data []byte) ParseResult {
	var result ParseResult

	switch eventType {
	case "response.output_item.added":
		var event OpenAIResponsesOutputItemAdded
		if err := json.Unmarshal(data, &event); err == nil {
			if event.Item.Type == contentTypeFunctionCall || event.Item.Type == contentTypeComputerCall {
				name := event.Item.Name
				if event.Item.Type == contentTypeComputerCall && name == "" {
					name = "computer" // Normalize: computer_call items may omit name
				}
				if p.sanitize && name != "" {
					name = rules.SanitizeToolName(name)
				}
				result.ToolCallStart = &ToolCallStartEvent{
					Index: event.OutputIndex,
					ID:    event.Item.CallID,
					Name:  name,
				}
			}
		}

	case "response.function_call_arguments.delta":
		var event OpenAIResponsesFunctionCallArgsDelta
		if err := json.Unmarshal(data, &event); err == nil {
			result.ToolCallDelta = &ToolCallDeltaEvent{
				Index:       event.OutputIndex,
				PartialJSON: event.Delta,
			}
		}

	case "response.output_text.delta":
		var event OpenAIResponsesOutputTextDelta
		if err := json.Unmarshal(data, &event); err == nil {
			if event.Delta != "" {
				result.TextContent = event.Delta
			}
		}

	case "response.completed":
		var event OpenAIResponsesCompleted
		if err := json.Unmarshal(data, &event); err == nil {
			result.InputTokens = max(0, event.Response.Usage.InputTokens)
			result.OutputTokens = max(0, event.Response.Usage.OutputTokens)
		}
	}

	return result
}

// ApplyResultToToolCalls updates a tool call map with the parse result.
// Returns true if a new tool call was started.
func (p *SSEParser) ApplyResultToToolCalls(result ParseResult, toolCalls map[int]*StreamingToolCall) bool {
	newToolCall := false

	if result.ToolCallStart != nil {
		tc, exists := toolCalls[result.ToolCallStart.Index]
		if !exists {
			tc = &StreamingToolCall{}
			toolCalls[result.ToolCallStart.Index] = tc
			newToolCall = true
		}
		if result.ToolCallStart.ID != "" {
			tc.ID = result.ToolCallStart.ID
		}
		if result.ToolCallStart.Name != "" {
			tc.Name = result.ToolCallStart.Name
		}
	}

	if result.ToolCallDelta != nil {
		if tc, exists := toolCalls[result.ToolCallDelta.Index]; exists {
			tc.Arguments.WriteString(result.ToolCallDelta.PartialJSON)
		}
	}

	return newToolCall
}
