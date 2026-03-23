package hookutil

import (
	"encoding/json"
	"testing"
)

func TestFormatResponse_Block(t *testing.T) {
	evalResult := `{"matched":true,"rule_name":"protect-persistence","severity":"critical","action":"block","message":"Blocked write to crontab"}`

	hookJSON := FormatResponse(evalResult)
	if hookJSON == "" {
		t.Fatal("expected non-empty hook JSON for a block result")
	}

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

func TestFormatResponse_Allow(t *testing.T) {
	if hookJSON := FormatResponse(`{"matched":false}`); hookJSON != "" {
		t.Errorf("expected empty for allow, got: %s", hookJSON)
	}
}

func TestFormatResponse_MatchedButNotBlock(t *testing.T) {
	if hookJSON := FormatResponse(`{"matched":true,"rule_name":"log-only-rule","action":"log","message":"Logged"}`); hookJSON != "" {
		t.Errorf("expected empty for action=log, got: %s", hookJSON)
	}
}

func TestFormatResponse_InvalidJSON(t *testing.T) {
	if hookJSON := FormatResponse("not{json"); hookJSON != "" {
		t.Errorf("expected empty for malformed input, got: %s", hookJSON)
	}
}

func TestFormatResponse_EmptyInput(t *testing.T) {
	if hookJSON := FormatResponse(""); hookJSON != "" {
		t.Errorf("expected empty for empty input, got: %s", hookJSON)
	}
}
