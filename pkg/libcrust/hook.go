package libcrust

import "encoding/json"

// hookResponse is the Claude Code PreToolUse hook output format.
// See https://docs.anthropic.com/en/docs/claude-code/hooks
type hookResponse struct {
	HookSpecificOutput hookSpecificOutput `json:"hookSpecificOutput"`
}

type hookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

// FormatHookResponse takes a raw eval result JSON (as returned by Evaluate)
// and returns the Claude Code PreToolUse hook response.
//
// Returns ("", false) if the tool call is allowed (no output needed).
// Returns (hookJSON, true) if the tool call is blocked.
//
// The hook protocol (https://docs.anthropic.com/en/docs/claude-code/hooks):
//   - Exit 0 with JSON containing hookSpecificOutput.permissionDecision: "deny" -> block
//   - Exit 0 with no JSON or permissionDecision: "allow" -> allow
//
// Fail-open: if the eval result is malformed or not a block, returns allowed.
func FormatHookResponse(evalResult string) (string, bool) {
	var result struct {
		Matched  bool   `json:"matched"`
		RuleName string `json:"rule_name"`
		Action   string `json:"action"`
		Message  string `json:"message"`
	}
	if err := json.Unmarshal([]byte(evalResult), &result); err != nil {
		return "", false // fail-open on malformed input
	}

	if !result.Matched || result.Action != "block" {
		return "", false // allowed
	}

	reason := "Blocked by Crust rule '" + result.RuleName + "': " + result.Message
	resp := hookResponse{
		HookSpecificOutput: hookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "deny",
			PermissionDecisionReason: reason,
		},
	}

	out, err := json.Marshal(resp)
	if err != nil {
		return "", false // fail-open on marshal error (shouldn't happen)
	}
	return string(out), true
}
