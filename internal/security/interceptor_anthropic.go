package security

import (
	"encoding/json"

	"github.com/BakeLens/crust/internal/message"
	"github.com/BakeLens/crust/internal/telemetry"
)

func (i *Interceptor) InterceptAnthropicResponse(responseBody []byte, ctx InterceptionContext) (*InterceptionResult, error) {
	return i.intercept(responseBody, ctx.BlockMode, func(result *InterceptionResult, useReplaceMode bool) (any, bool) {
		var resp anthropicResponse
		if err := json.Unmarshal(responseBody, &resp); err != nil {
			log.Warn("[Layer1] Failed to parse %s response: %v", ctx.APIType, err)
			return nil, false
		}
		allowed := make([]anthropicContentBlock, 0, len(resp.Content))
		modified := false
		for _, block := range resp.Content {
			if block.Type != contentTypeToolUse {
				allowed = append(allowed, block)
				continue
			}
			tc := telemetry.ToolCall{ID: block.ID, Name: block.Name, Arguments: block.Input}
			matchResult, blocked := i.evaluateToolCall(result, tc, ctx, string(block.Input), useReplaceMode)
			if blocked {
				modified = true
				if useReplaceMode {
					allowed = append(allowed, anthropicContentBlock{Type: "text", Text: message.FormatReplaceInline(block.Name, matchResult)})
				}
			} else {
				allowed = append(allowed, block)
			}
		}
		if len(result.BlockedToolCalls) > 0 && !useReplaceMode {
			allowed = append(allowed, anthropicContentBlock{Type: "text", Text: message.FormatRemoveWarning(toBlockedCalls(result.BlockedToolCalls))})
			modified = true
		}
		resp.Content = allowed
		return resp, modified
	})
}

type anthropicResponse struct {
	ID           string                  `json:"id,omitempty"`
	Type         string                  `json:"type,omitempty"`
	Role         string                  `json:"role,omitempty"`
	Content      []anthropicContentBlock `json:"content,omitempty"`
	Model        string                  `json:"model,omitempty"`
	StopReason   string                  `json:"stop_reason,omitempty"`
	StopSequence string                  `json:"stop_sequence,omitempty"`
	Usage        *anthropicUsage         `json:"usage,omitempty"`
}

type anthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type anthropicContentBlock struct {
	Type  string          `json:"type"`
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
	Text  string          `json:"text,omitempty"`
}
