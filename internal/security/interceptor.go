package security

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync/atomic"

	"github.com/BakeLens/crust/internal/eventlog"
	"github.com/BakeLens/crust/internal/message"
	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/types"
)

// API-specific protocol constants for content block types.
const (
	contentTypeToolUse      = "tool_use"      // Anthropic
	contentTypeFunctionCall = "function_call" // OpenAI Responses
)

// Interceptor handles tool call interception and response modification
type Interceptor struct {
	engine  *rules.Engine
	storage telemetry.Recorder
	enabled atomic.Bool
}

// NewInterceptor creates a new interceptor
func NewInterceptor(engine *rules.Engine, storage telemetry.Recorder) *Interceptor {
	i := &Interceptor{
		engine:  engine,
		storage: storage,
	}
	i.enabled.Store(true)
	return i
}

// SetEnabled enables or disables the interceptor
func (i *Interceptor) SetEnabled(enabled bool) {
	i.enabled.Store(enabled)
}

// IsEnabled returns whether the interceptor is enabled
func (i *Interceptor) IsEnabled() bool {
	return i.enabled.Load()
}

// GetEngine returns the rule engine
func (i *Interceptor) GetEngine() *rules.Engine {
	return i.engine
}

// GetStorage returns the storage recorder
func (i *Interceptor) GetStorage() telemetry.Recorder {
	return i.storage
}

// InterceptionResult contains the result of intercepting tool calls
type InterceptionResult struct {
	ModifiedResponse []byte
	BlockedToolCalls []BlockedToolCall
	AllowedToolCalls []telemetry.ToolCall
}

// BlockedToolCall represents a tool call that was blocked
type BlockedToolCall struct {
	ToolCall    telemetry.ToolCall
	MatchResult rules.MatchResult
}

// InterceptionContext holds request metadata used for evaluation and telemetry.
type InterceptionContext struct {
	TraceID   types.TraceID
	SessionID types.SessionID
	Model     string
	APIType   types.APIType
	BlockMode types.BlockMode
}

// intercept is the shared implementation for all three Intercept* format methods.
// It handles the guard check, result initialization, and final marshal.
// fn receives the result and useReplaceMode, applies format-specific filtering,
// and returns the (possibly modified) response value and whether it changed.
// Returning (nil, false) — e.g. on JSON parse failure — passes the original body through.
// Returning (nil, true) is treated the same way (silent passthrough); fn must not
// return modified=true with a nil response.
func (i *Interceptor) intercept(
	responseBody []byte,
	blockMode types.BlockMode,
	fn func(result *InterceptionResult, useReplaceMode bool) (any, bool),
) (*InterceptionResult, error) {
	if !i.enabled.Load() || i.engine == nil {
		return &InterceptionResult{ModifiedResponse: responseBody}, nil
	}
	result := &InterceptionResult{
		BlockedToolCalls: make([]BlockedToolCall, 0),
		AllowedToolCalls: make([]telemetry.ToolCall, 0),
	}
	resp, modified := fn(result, blockMode.IsReplace())
	if !modified || resp == nil {
		result.ModifiedResponse = responseBody
		return result, nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(resp); err != nil {
		return &InterceptionResult{ModifiedResponse: responseBody}, err
	}
	b := buf.Bytes()
	result.ModifiedResponse = b[:len(b)-1] // strip trailing newline from json.Encoder
	return result, nil
}

// InterceptToolCalls intercepts tool calls based on API type.
// ctx.BlockMode: types.BlockModeRemove (delete tool calls) or types.BlockModeReplace (substitute with a text warning block)
func (i *Interceptor) InterceptToolCalls(responseBody []byte, ctx InterceptionContext) (*InterceptionResult, error) {
	switch ctx.APIType {
	case types.APITypeAnthropic:
		return i.InterceptAnthropicResponse(responseBody, ctx)
	case types.APITypeOpenAIResponses:
		return i.InterceptOpenAIResponsesResponse(responseBody, ctx)
	case types.APITypeOpenAICompletion, types.APITypeUnknown:
		return i.InterceptOpenAIResponse(responseBody, ctx)
	default:
		return nil, fmt.Errorf("unhandled API type: %s", ctx.APIType)
	}
}

// evaluateToolCall evaluates a single tool call against the rules engine.
// Returns the match result. Handles logging, metrics, and result bookkeeping.
// Returns true if the tool call was blocked.
func (i *Interceptor) evaluateToolCall(
	result *InterceptionResult,
	tc telemetry.ToolCall,
	ctx InterceptionContext,
	argsString string,
	useReplaceMode bool,
) (rules.MatchResult, bool) {
	matchResult := i.engine.Evaluate(rules.ToolCall{
		Name:      tc.Name,
		Arguments: tc.Arguments,
	})

	isBlocked := matchResult.Matched && matchResult.Action == rules.ActionBlock
	ruleName := ""
	if matchResult.Matched {
		ruleName = matchResult.RuleName
	}

	eventlog.Record(eventlog.Event{
		Layer:      eventlog.LayerProxyResponse,
		TraceID:    ctx.TraceID,
		SessionID:  ctx.SessionID,
		ToolName:   tc.Name,
		Arguments:  json.RawMessage(argsString),
		APIType:    ctx.APIType,
		Model:      ctx.Model,
		WasBlocked: isBlocked,
		RuleName:   ruleName,
	})

	if isBlocked {
		result.BlockedToolCalls = append(result.BlockedToolCalls, BlockedToolCall{
			ToolCall:    tc,
			MatchResult: matchResult,
		})
		if useReplaceMode {
			log.Warn("[Layer1] Replaced: %s (rule: %s)", tc.Name, matchResult.RuleName)
		} else {
			log.Warn("[Layer1] Blocked: %s (rule: %s)", tc.Name, matchResult.RuleName)
		}
		return matchResult, true
	}

	result.AllowedToolCalls = append(result.AllowedToolCalls, tc)
	return matchResult, false
}

// BuildWarningContent builds a warning message listing blocked tool calls.
// Delegates to message.FormatRemoveWarning for centralized formatting.
func BuildWarningContent(blockedCalls []BlockedToolCall) string {
	return message.FormatRemoveWarning(toBlockedCalls(blockedCalls))
}

// toBlockedCalls converts []BlockedToolCall to []message.BlockedCall.
func toBlockedCalls(blockedCalls []BlockedToolCall) []message.BlockedCall {
	out := make([]message.BlockedCall, len(blockedCalls))
	for i, bc := range blockedCalls {
		out[i] = message.BlockedCall{
			ToolName:    bc.ToolCall.Name,
			MatchResult: bc.MatchResult,
		}
	}
	return out
}
