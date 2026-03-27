package httpproxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"

	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/types"
)

// extractToolCalls parses API-specific response bodies and returns tool calls.
func extractToolCalls(bodyBytes []byte, apiType types.APIType) []telemetry.ToolCall {
	var toolCalls []telemetry.ToolCall

	if len(bodyBytes) == 0 {
		return toolCalls
	}

	switch apiType {
	case types.APITypeOpenAICompletion:
		var resp struct {
			Choices []struct {
				Message struct {
					ToolCalls []struct {
						ID       string `json:"id"`
						Function struct {
							Name      string          `json:"name"`
							Arguments json.RawMessage `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(bodyBytes, &resp); err == nil {
			for _, choice := range resp.Choices {
				for _, tc := range choice.Message.ToolCalls {
					toolCalls = append(toolCalls, telemetry.ToolCall{
						ID:        tc.ID,
						Name:      tc.Function.Name,
						Arguments: tc.Function.Arguments,
					})
				}
			}
		}

	case types.APITypeAnthropic:
		var resp struct {
			Content []struct {
				Type  string          `json:"type"`
				ID    string          `json:"id"`
				Name  string          `json:"name"`
				Input json.RawMessage `json:"input"`
			} `json:"content"`
		}
		if err := json.Unmarshal(bodyBytes, &resp); err == nil {
			for _, c := range resp.Content {
				if c.Type == contentTypeToolUse {
					toolCalls = append(toolCalls, telemetry.ToolCall{
						ID:        c.ID,
						Name:      c.Name,
						Arguments: c.Input,
					})
				}
			}
		}

	case types.APITypeOpenAIResponses:
		var resp struct {
			Output []struct {
				Type      string `json:"type"`
				CallID    string `json:"call_id"`
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			} `json:"output"`
		}
		if err := json.Unmarshal(bodyBytes, &resp); err == nil {
			for _, item := range resp.Output {
				if item.Type == contentTypeFunctionCall || item.Type == contentTypeComputerCall {
					name := item.Name
					if item.Type == contentTypeComputerCall && name == "" {
						name = "computer"
					}
					toolCalls = append(toolCalls, telemetry.ToolCall{
						ID:        item.CallID,
						Name:      name,
						Arguments: json.RawMessage(item.Arguments),
					})
				}
			}
		}

	case types.APITypeUnknown:
		// no tool calls for unknown types
	}

	return toolCalls
}

// marshalContentJSON builds a {"content":"..."} JSON object safely using
// json.Marshal for the value, avoiding manual string concatenation that
// static analyzers (CodeQL) flag as potentially unsafe quoting.
func marshalContentJSON(content string) json.RawMessage {
	obj := struct {
		Content string `json:"content"`
	}{Content: content}
	b, err := json.Marshal(obj)
	if err != nil {
		return json.RawMessage(`{"content":""}`)
	}
	return b
}

// computeSessionID generates a session ID from system prompt and first user message
// Same session will have the same system prompt + first user message, so the hash is stable
func computeSessionID(messages []requestMessage) string {
	var sb strings.Builder

	// Extract system prompt
	for _, msg := range messages {
		if msg.Role == types.RoleSystem {
			sb.WriteString(msg.ContentString())
			break
		}
	}

	// Extract first user message
	for _, msg := range messages {
		if msg.Role == types.RoleUser {
			sb.WriteString(msg.ContentString())
			break
		}
	}

	// If no messages, return empty (will fall back to traceID)
	if sb.Len() == 0 {
		return ""
	}

	// SHA256 hash, take first 8 bytes (16 hex chars)
	h := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(h[:8])
}

// extractMessageTextsFromJSON walks raw JSON to extract all text content from
// messages in the request body. This catches secrets embedded in conversation
// history (tool results, user messages, assistant messages) that are not inside
// tool call argument objects — those are handled by Layer 1 response-side evaluation.
//
// Supports all three API formats:
//   - Anthropic Messages: messages[].content (string or content block array)
//   - OpenAI Chat: messages[].content (string)
//   - OpenAI Responses: input[].content / input[].output
//
// maxDLPScanSize limits the total text extracted for DLP scanning to prevent
// excessive CPU usage on large conversation histories.
const maxDLPScanSize = 512 * 1024 // 512KB

func extractMessageTextsFromJSON(data []byte) []string {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	texts := make([]string, 0, 16)
	totalSize := 0
	// Handle top-level "system" field (Anthropic Messages API).
	// Can be a plain string or an array of content blocks.
	if system, ok := raw["system"]; ok {
		collectTextsFromContent(system, &texts)
		for _, t := range texts {
			totalSize += len(t)
		}
	}
	// Handle "messages" array (Anthropic + OpenAI Chat)
	if messages, ok := raw["messages"].([]any); ok {
		for _, msg := range messages {
			if totalSize >= maxDLPScanSize {
				break
			}
			msgObj, ok := msg.(map[string]any)
			if !ok {
				continue
			}
			before := len(texts)
			collectTextsFromContent(msgObj["content"], &texts)
			for _, t := range texts[before:] {
				totalSize += len(t)
			}
		}
	}
	// Handle "input" array (OpenAI Responses)
	if input, ok := raw["input"].([]any); ok {
		for _, item := range input {
			if totalSize >= maxDLPScanSize {
				break
			}
			itemObj, ok := item.(map[string]any)
			if !ok {
				continue
			}
			before := len(texts)
			collectTextsFromContent(itemObj["content"], &texts)
			// function_call_output items store result in "output"
			if output, ok := itemObj["output"].(string); ok {
				texts = append(texts, output)
			}
			for _, t := range texts[before:] {
				totalSize += len(t)
			}
		}
	}
	return texts
}

// collectTextsFromContent extracts text strings from a message content field.
// Handles both plain string content and Anthropic-style content block arrays
// (text blocks, tool_result blocks with nested content).
func collectTextsFromContent(content any, texts *[]string) {
	if content == nil {
		return
	}
	// Plain string content
	if s, ok := content.(string); ok {
		*texts = append(*texts, s)
		return
	}
	// Array content (Anthropic content blocks)
	arr, ok := content.([]any)
	if !ok {
		return
	}
	for _, block := range arr {
		blockObj, ok := block.(map[string]any)
		if !ok {
			continue
		}
		// text blocks: {"type": "text", "text": "..."}
		if text, ok := blockObj["text"].(string); ok {
			*texts = append(*texts, text)
		}
		// tool_result blocks: {"type": "tool_result", "content": "..."}
		if blockObj["type"] == "tool_result" {
			collectTextsFromContent(blockObj["content"], texts)
		}
	}
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
