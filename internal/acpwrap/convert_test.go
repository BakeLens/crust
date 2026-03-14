package acpwrap

import (
	"encoding/json"
	"testing"
)

// --- ACPMethodToToolCall ---

func TestAcpMethodToToolCall(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		params   string
		wantName string
		wantKey  string
		wantVal  string
	}{
		{"fs_read", "fs/read_text_file", `{"sessionId":"s1","path":"/etc/passwd"}`, "read_file", "path", "/etc/passwd"},
		{"fs_write", "fs/write_text_file", `{"sessionId":"s1","path":"/home/user/.env","content":"SECRET=abc"}`, "write_file", "path", "/home/user/.env"},
		{"terminal", "terminal/create", `{"sessionId":"s1","command":"rm","args":["-rf","/"]}`, "bash", "command", "rm -rf /"},
		{"terminal_no_args", "terminal/create", `{"sessionId":"s1","command":"ls"}`, "bash", "command", "ls"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc, err := ACPMethodToToolCall(tt.method, json.RawMessage(tt.params))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc == nil {
				t.Fatal("expected non-nil ToolCall")
				return
			}
			if tc.Name != tt.wantName {
				t.Errorf("name = %s, want %s", tc.Name, tt.wantName)
			}
			var args map[string]any
			if err := json.Unmarshal(tc.Arguments, &args); err != nil {
				t.Fatal(err)
			}
			if got := args[tt.wantKey]; got != tt.wantVal {
				t.Errorf("%s = %v, want %s", tt.wantKey, got, tt.wantVal)
			}
		})
	}
}

func TestAcpMethodToToolCall_Unknown(t *testing.T) {
	for _, method := range []string{"session/prompt", "initialize", "fs/delete"} {
		tc, err := ACPMethodToToolCall(method, nil)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", method, err)
		}
		if tc != nil {
			t.Errorf("%s should not be security-relevant", method)
		}
	}
}

func TestAcpMethodToToolCall_EmptyCommand(t *testing.T) {
	// Bug #18: terminal/create with empty command should return an error.
	tests := []struct {
		name   string
		params string
	}{
		{"empty_command", `{"sessionId":"s1","command":""}`},
		{"missing_command", `{"sessionId":"s1"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc, err := ACPMethodToToolCall("terminal/create", json.RawMessage(tt.params))
			if err == nil {
				t.Error("expected error for empty command, got nil")
			}
			if tc != nil {
				t.Errorf("expected nil ToolCall, got %+v", tc)
			}
		})
	}
}

func TestAcpMethodToToolCall_MalformedParams(t *testing.T) {
	methods := []string{"fs/read_text_file", "fs/write_text_file", "terminal/create"}
	badInputs := []json.RawMessage{
		json.RawMessage(`{broken`),
		json.RawMessage(`"just a string"`),
		json.RawMessage(`null`),
		json.RawMessage(`42`),
		json.RawMessage(``),
	}
	for _, method := range methods {
		for _, input := range badInputs {
			tc, err := ACPMethodToToolCall(method, input)
			if tc != nil {
				t.Errorf("%s with %q: expected nil ToolCall for malformed params", method, input)
			}
			if err == nil {
				t.Errorf("%s with %q: expected error for malformed params", method, input)
			}
		}
	}
}
