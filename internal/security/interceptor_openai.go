package security

import (
	"encoding/json"

	"github.com/BakeLens/crust/internal/message"
	"github.com/BakeLens/crust/internal/telemetry"
)

func (i *Interceptor) InterceptOpenAIResponse(responseBody []byte, ctx InterceptionContext) (*InterceptionResult, error) {
	return i.intercept(responseBody, ctx.BlockMode, func(result *InterceptionResult, useReplaceMode bool) (any, bool) {
		var resp openAIResponse
		if err := json.Unmarshal(responseBody, &resp); err != nil {
			log.Warn("[Layer1] Failed to parse %s response: %v", ctx.APIType, err)
			return nil, false
		}
		modified := false
		for choiceIdx := range resp.Choices {
			choice := &resp.Choices[choiceIdx]
			if choice.Message.ToolCalls == nil {
				continue
			}
			allowed := make([]openAIToolCall, 0, len(choice.Message.ToolCalls))
			for _, tc := range choice.Message.ToolCalls {
				toolCall := telemetry.ToolCall{ID: tc.ID, Name: tc.Function.Name, Arguments: json.RawMessage(tc.Function.Arguments)}
				_, blocked := i.evaluateToolCall(result, toolCall, ctx, tc.Function.Arguments, useReplaceMode)
				if blocked {
					modified = true
				} else {
					allowed = append(allowed, tc)
				}
			}
			choice.Message.ToolCalls = allowed
		}
		if len(result.BlockedToolCalls) > 0 && len(resp.Choices) > 0 {
			var msg string
			if useReplaceMode {
				msg = message.FormatReplaceWarning(toBlockedCalls(result.BlockedToolCalls))
			} else {
				msg = message.FormatRemoveWarning(toBlockedCalls(result.BlockedToolCalls))
			}
			if resp.Choices[0].Message.Content == "" {
				resp.Choices[0].Message.Content = msg
			} else {
				resp.Choices[0].Message.Content += "\n\n" + msg
			}
			modified = true
		}
		return resp, modified
	})
}

func (i *Interceptor) InterceptOpenAIResponsesResponse(responseBody []byte, ctx InterceptionContext) (*InterceptionResult, error) {
	return i.intercept(responseBody, ctx.BlockMode, func(result *InterceptionResult, useReplaceMode bool) (any, bool) {
		var resp openAIResponsesResponse
		if err := json.Unmarshal(responseBody, &resp); err != nil {
			log.Warn("[Layer1] Failed to parse %s response: %v", ctx.APIType, err)
			return nil, false
		}
		allowed := make([]openAIResponsesOutputItem, 0, len(resp.Output))
		modified := false
		for _, item := range resp.Output {
			if item.Type != contentTypeFunctionCall {
				allowed = append(allowed, item)
				continue
			}
			tc := telemetry.ToolCall{ID: item.CallID, Name: item.Name, Arguments: json.RawMessage(item.Arguments)}
			matchResult, blocked := i.evaluateToolCall(result, tc, ctx, item.Arguments, useReplaceMode)
			if blocked {
				modified = true
				if useReplaceMode {
					allowed = append(allowed, openAIResponsesOutputItem{
						Type: "message", ID: item.ID,
						Content: []openAIResponsesContent{{Type: "output_text", Text: message.FormatReplaceInline(item.Name, matchResult)}},
					})
				}
			} else {
				allowed = append(allowed, item)
			}
		}
		if len(result.BlockedToolCalls) > 0 && !useReplaceMode {
			allowed = append(allowed, openAIResponsesOutputItem{
				Type:    "message",
				Content: []openAIResponsesContent{{Type: "output_text", Text: message.FormatRemoveWarning(toBlockedCalls(result.BlockedToolCalls))}},
			})
			modified = true
		}
		resp.Output = allowed
		return resp, modified
	})
}

type openAIResponse struct {
	ID      string         `json:"id,omitempty"`
	Object  string         `json:"object,omitempty"`
	Created int64          `json:"created,omitempty"`
	Model   string         `json:"model,omitempty"`
	Choices []openAIChoice `json:"choices,omitempty"`
	Usage   *openAIUsage   `json:"usage,omitempty"`
}

type openAIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type openAIChoice struct {
	Index        int            `json:"index"`
	Message      openAIMessage  `json:"message,omitzero"`
	Delta        *openAIMessage `json:"delta,omitempty"`
	FinishReason string         `json:"finish_reason,omitempty"`
}

type openAIMessage struct {
	Role      string           `json:"role,omitempty"`
	Content   string           `json:"content,omitempty"`
	ToolCalls []openAIToolCall `json:"tool_calls,omitempty"`
}

type openAIToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type openAIResponsesResponse struct {
	ID     string                      `json:"id,omitempty"`
	Object string                      `json:"object,omitempty"`
	Model  string                      `json:"model,omitempty"`
	Output []openAIResponsesOutputItem `json:"output,omitempty"`
	Usage  *openAIResponsesUsage       `json:"usage,omitempty"`
}

type openAIResponsesOutputItem struct {
	Type      string                   `json:"type"`
	ID        string                   `json:"id,omitempty"`
	CallID    string                   `json:"call_id,omitempty"`
	Name      string                   `json:"name,omitempty"`
	Arguments string                   `json:"arguments,omitempty"`
	Content   []openAIResponsesContent `json:"content,omitempty"`
}

type openAIResponsesContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type openAIResponsesUsage struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
}
