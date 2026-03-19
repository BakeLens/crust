package mcpgateway

import (
	"github.com/BakeLens/crust/internal/jsonrpc"
	"github.com/BakeLens/crust/internal/message"
	"github.com/BakeLens/crust/internal/rules"
)

// InspectDecision indicates the inspection outcome for a JSON-RPC message.
type InspectDecision int

const (
	// Forward means the message should be forwarded to the other side.
	Forward InspectDecision = iota
	// Block means the message should be blocked and a JSON-RPC error returned.
	Block
	// LogOnly means the message matched a log-only rule; forward but log the match.
	LogOnly
)

// InspectResult holds the inspection outcome for a single JSON-RPC message.
type InspectResult struct {
	Decision InspectDecision
	BlockMsg string // formatted error message for JSON-RPC error (Block only)
	RuleName string // matched rule name (Block and LogOnly)
	ToolName string // converted tool call name (if applicable)
}

// InspectRequest evaluates a JSON-RPC request or notification against MCP security rules.
// It converts the message using MCPMethodToToolCall, evaluates against the rule engine,
// and DLP-scans notification params.
//
// For responses (no method), use InspectResponse instead.
func InspectRequest(engine rules.RuleEvaluator, msg *jsonrpc.Message) InspectResult {
	// Notifications: DLP-scan params for leaked secrets first.
	if msg.IsNotification() {
		if dlp := engine.ScanDLP(string(msg.Params)); dlp != nil {
			return InspectResult{
				Decision: Block,
				BlockMsg: message.FormatDLPBlock(dlp.RuleName, dlp.Message),
				RuleName: dlp.RuleName,
			}
		}
	}

	// Convert MCP method → ToolCall for rule evaluation.
	toolCall, err := MCPMethodToToolCall(msg.Method, msg.Params)
	if toolCall == nil && err == nil {
		// Not a security-relevant method — pass through.
		return InspectResult{Decision: Forward}
	}
	if err != nil || toolCall == nil {
		return InspectResult{
			Decision: Block,
			BlockMsg: message.FormatProtocolError("malformed params for " + msg.Method),
		}
	}

	result := engine.Evaluate(*toolCall)

	if result.Matched && result.Action == rules.ActionBlock {
		return InspectResult{
			Decision: Block,
			BlockMsg: message.FormatJSONRPCBlock(result.RuleName, result.Message),
			RuleName: result.RuleName,
			ToolName: toolCall.Name,
		}
	}

	if result.Matched && result.Action == rules.ActionLog {
		return InspectResult{
			Decision: LogOnly,
			RuleName: result.RuleName,
			ToolName: toolCall.Name,
		}
	}

	return InspectResult{Decision: Forward, ToolName: toolCall.Name}
}

// InspectResponse DLP-scans a JSON-RPC response's result and error fields.
// Returns Block if either field contains leaked secrets.
func InspectResponse(engine rules.RuleEvaluator, msg *jsonrpc.Message) InspectResult {
	if len(msg.Result) > 0 {
		if dlp := engine.ScanDLP(string(msg.Result)); dlp != nil {
			return InspectResult{
				Decision: Block,
				BlockMsg: message.FormatDLPBlock(dlp.RuleName, dlp.Message),
				RuleName: dlp.RuleName,
			}
		}
	}
	if len(msg.Error) > 0 {
		if dlp := engine.ScanDLP(string(msg.Error)); dlp != nil {
			return InspectResult{
				Decision: Block,
				BlockMsg: message.FormatDLPBlock(dlp.RuleName, dlp.Message),
				RuleName: dlp.RuleName,
			}
		}
	}
	return InspectResult{Decision: Forward}
}
