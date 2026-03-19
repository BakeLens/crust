package httpproxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"

	"github.com/BakeLens/crust/internal/rules"
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
				if item.Type == contentTypeFunctionCall {
					toolCalls = append(toolCalls, telemetry.ToolCall{
						ID:        item.CallID,
						Name:      item.Name,
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

// maxJSONWalkDepth limits recursion depth in walkJSONForToolCalls to prevent
// stack overflow from adversarially nested JSON. Tool calls in real API
// requests are at most ~5 levels deep; 64 is generous.
const maxJSONWalkDepth = 64

// extractToolCallsFromJSON walks raw JSON to find tool call objects across
// all API formats (OpenAI Chat, Anthropic Messages, OpenAI Responses) without
// format-specific struct parsing.
func extractToolCallsFromJSON(data []byte) []rules.ToolCall {
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	var results []rules.ToolCall
	walkJSONForToolCalls(raw, &results, 0)
	if len(results) > 0 {
		log.Debug("extractToolCallsFromJSON: found %d tool calls", len(results))
	}
	return results
}

func walkJSONForToolCalls(v any, results *[]rules.ToolCall, depth int) {
	if depth > maxJSONWalkDepth {
		return
	}
	switch val := v.(type) {
	case map[string]any:
		// Pattern 1: type=tool_use (Anthropic)
		// Pattern 2: type=function_call (OpenAI Responses)
		matched := false
		if tc, ok := matchTypedToolCall(val); ok {
			*results = append(*results, tc)
			matched = true
		}
		// Pattern 3: function.{name, arguments} (OpenAI Chat)
		// Skip if already matched as typed tool call to avoid double-counting.
		if !matched {
			if fn, ok := val["function"].(map[string]any); ok {
				if tc, ok := matchFunctionObject(fn); ok {
					*results = append(*results, tc)
				}
			}
		}
		// Recurse into all values
		for _, child := range val {
			walkJSONForToolCalls(child, results, depth+1)
		}
	case []any:
		for _, child := range val {
			walkJSONForToolCalls(child, results, depth+1)
		}
	}
}

func matchTypedToolCall(obj map[string]any) (rules.ToolCall, bool) {
	t, _ := obj["type"].(string)
	name, _ := obj["name"].(string)
	if name == "" {
		return rules.ToolCall{}, false
	}
	switch t {
	case contentTypeToolUse:
		// Anthropic: input is a JSON object
		return rules.ToolCall{Name: name, Arguments: toRawMessage(obj["input"])}, true
	case contentTypeFunctionCall:
		// OpenAI Responses: arguments is a JSON string
		return rules.ToolCall{Name: name, Arguments: toRawMessage(obj["arguments"])}, true
	}
	return rules.ToolCall{}, false
}

func matchFunctionObject(fn map[string]any) (rules.ToolCall, bool) {
	name, _ := fn["name"].(string)
	if name == "" {
		return rules.ToolCall{}, false
	}
	_, hasArgs := fn["arguments"]
	if !hasArgs {
		return rules.ToolCall{}, false
	}
	return rules.ToolCall{Name: name, Arguments: toRawMessage(fn["arguments"])}, true
}

// toRawMessage converts a value to json.RawMessage.
// If the value is a string, it's treated as already-encoded JSON arguments.
// Otherwise, it's marshaled to JSON.
func toRawMessage(v any) json.RawMessage {
	if v == nil {
		return nil
	}
	if s, ok := v.(string); ok {
		if json.Valid([]byte(s)) {
			return json.RawMessage(s)
		}
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
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
