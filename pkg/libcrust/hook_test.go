package libcrust

import (
	"encoding/json"
	"testing"
)

func TestFormatHookResponse_Block(t *testing.T) {
	evalResult := `{"matched":true,"rule_name":"protect-persistence","severity":"critical","action":"block","message":"Blocked write to crontab"}`

	hookJSON := FormatHookResponse(evalResult)
	if hookJSON == "" {
		t.Fatal("expected non-empty hook JSON for a block result")
	}

	// Verify the JSON structure matches the hook protocol.
	var resp struct {
		HookSpecificOutput struct {
			HookEventName            string `json:"hookEventName"`
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(hookJSON), &resp); err != nil {
		t.Fatalf("invalid hook JSON: %v\n%s", err, hookJSON)
	}

	if resp.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Errorf("hookEventName = %q, want PreToolUse", resp.HookSpecificOutput.HookEventName)
	}
	if resp.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("permissionDecision = %q, want deny", resp.HookSpecificOutput.PermissionDecision)
	}
	want := "Blocked by Crust rule 'protect-persistence': Blocked write to crontab"
	if resp.HookSpecificOutput.PermissionDecisionReason != want {
		t.Errorf("permissionDecisionReason = %q, want %q", resp.HookSpecificOutput.PermissionDecisionReason, want)
	}
}

func TestFormatHookResponse_Allow(t *testing.T) {
	hookJSON := FormatHookResponse(`{"matched":false}`)
	if hookJSON != "" {
		t.Errorf("expected empty hook JSON for allow, got: %s", hookJSON)
	}
}

func TestFormatHookResponse_MatchedButNotBlock(t *testing.T) {
	hookJSON := FormatHookResponse(`{"matched":true,"rule_name":"log-only-rule","action":"log","message":"Logged"}`)
	if hookJSON != "" {
		t.Errorf("expected empty hook JSON for action=log, got: %s", hookJSON)
	}
}

func TestFormatHookResponse_InvalidJSON(t *testing.T) {
	hookJSON := FormatHookResponse("not{json")
	if hookJSON != "" {
		t.Errorf("expected empty hook JSON for malformed input, got: %s", hookJSON)
	}
}

func TestFormatHookResponse_EmptyInput(t *testing.T) {
	hookJSON := FormatHookResponse("")
	if hookJSON != "" {
		t.Errorf("expected empty hook JSON for empty input, got: %s", hookJSON)
	}
}
