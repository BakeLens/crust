package plugin

import (
	"context"
	"time"

	"github.com/BakeLens/crust/internal/rules"
)

// WirePluginPostChecker connects a plugin registry to the engine's PostChecker
// so that all evaluation paths (HTTP proxy, MCP/ACP wrap, hook, direct Evaluate)
// automatically consult plugins after the built-in rules allow a tool call.
func WirePluginPostChecker(engine *rules.Engine, registry *Registry) {
	engine.SetPostChecker(func(call rules.ToolCall, info rules.ExtractedInfo) *rules.MatchResult {
		if registry == nil {
			return nil
		}
		req := BuildPluginRequest(engine, call, info)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result := registry.Evaluate(ctx, req)
		if result == nil {
			return nil
		}
		m := rules.NewMatch(result.RuleName, result.Severity, result.Action, result.Message)
		return &m
	})
}

// BuildPluginRequest constructs a plugin.Request from a tool call and extracted info.
func BuildPluginRequest(e *rules.Engine, call rules.ToolCall, info rules.ExtractedInfo) Request {
	engineRules := e.GetRules()
	snapshots := make([]RuleSnapshot, len(engineRules))
	for i := range engineRules {
		snapshots[i] = SnapshotRule(&engineRules[i])
	}

	return Request{
		ToolName:   call.Name,
		Arguments:  call.Arguments,
		Operation:  info.Operation,
		Operations: info.Operations,
		Command:    info.Command,
		Paths:      info.Paths,
		Hosts:      info.Hosts,
		Content:    info.Content,
		Evasive:    info.Evasive,
		Rules:      snapshots,
	}
}
