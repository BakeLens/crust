package libcrust

import (
	"encoding/json"
	"testing"
)

func TestFormatHookResponse_Block(t *testing.T) {
	evalResult := `{"matched":true,"rule_name":"protect-persistence","severity":"critical","action":"block","message":"Blocked write to crontab"}`

	hookJSON, blocked := FormatHookResponse(evalResult)
	if !blocked {
		t.Fatal("expected blocked=true for a block result")
	}
	if hookJSON == "" {
		t.Fatal("expected non-empty hook JSON for a block result")
	}

	// Verify the JSON structure matches Claude Code hook protocol.
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
	if resp.HookSpecificOutput.PermissionDecisionReason == "" {
		t.Error("permissionDecisionReason should not be empty")
	}
	// Verify the reason includes both rule name and message.
	want := "Blocked by Crust rule 'protect-persistence': Blocked write to crontab"
	if resp.HookSpecificOutput.PermissionDecisionReason != want {
		t.Errorf("permissionDecisionReason = %q, want %q", resp.HookSpecificOutput.PermissionDecisionReason, want)
	}
}

func TestFormatHookResponse_Allow(t *testing.T) {
	evalResult := `{"matched":false}`

	hookJSON, blocked := FormatHookResponse(evalResult)
	if blocked {
		t.Error("expected blocked=false for an allow result")
	}
	if hookJSON != "" {
		t.Errorf("expected empty hook JSON for allow, got: %s", hookJSON)
	}
}

func TestFormatHookResponse_MatchedButNotBlock(t *testing.T) {
	// A rule that matched but has action=log should be allowed through.
	evalResult := `{"matched":true,"rule_name":"log-only-rule","action":"log","message":"Logged"}`

	hookJSON, blocked := FormatHookResponse(evalResult)
	if blocked {
		t.Error("expected blocked=false for action=log")
	}
	if hookJSON != "" {
		t.Errorf("expected empty hook JSON for action=log, got: %s", hookJSON)
	}
}

func TestFormatHookResponse_InvalidJSON(t *testing.T) {
	// Malformed input should fail open (allowed).
	hookJSON, blocked := FormatHookResponse("not{json")
	if blocked {
		t.Error("expected blocked=false for malformed JSON (fail-open)")
	}
	if hookJSON != "" {
		t.Errorf("expected empty hook JSON for malformed input, got: %s", hookJSON)
	}
}

func TestFormatHookResponse_EmptyInput(t *testing.T) {
	hookJSON, blocked := FormatHookResponse("")
	if blocked {
		t.Error("expected blocked=false for empty input (fail-open)")
	}
	if hookJSON != "" {
		t.Errorf("expected empty hook JSON for empty input, got: %s", hookJSON)
	}
}
