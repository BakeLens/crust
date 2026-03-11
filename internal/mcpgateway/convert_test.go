package mcpgateway

import (
	"encoding/json"
	"testing"
)

// --- MCPMethodToToolCall ---

func TestMcpMethodToToolCall(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		params   string
		wantName string
		wantKey  string
		wantVal  string
	}{
		{
			"tools_call_read_file",
			"tools/call",
			`{"name":"read_file","arguments":{"path":"/etc/passwd"}}`,
			"read_file", "path", "/etc/passwd",
		},
		{
			"tools_call_write_file",
			"tools/call",
			`{"name":"write_file","arguments":{"path":"/tmp/out.txt","content":"hello"}}`,
			"write_file", "path", "/tmp/out.txt",
		},
		{
			"tools_call_bash",
			"tools/call",
			`{"name":"bash","arguments":{"command":"ls -la"}}`,
			"bash", "command", "ls -la",
		},
		{
			"tools_call_custom_tool",
			"tools/call",
			`{"name":"my_custom_tool","arguments":{"query":"SELECT * FROM users"}}`,
			"my_custom_tool", "query", "SELECT * FROM users",
		},
		{
			"resources_read_file",
			"resources/read",
			`{"uri":"file:///etc/passwd"}`,
			"read_file", "path", "/etc/passwd",
		},
		{
			"resources_read_http",
			"resources/read",
			`{"uri":"https://evil.com/data"}`,
			"mcp_resource_read", "url", "https://evil.com/data",
		},
		{
			"resources_read_windows_backslash",
			"resources/read",
			`{"uri":"C:\\Users\\me\\.ssh\\id_rsa"}`,
			"read_file", "path", "C:/Users/me/.ssh/id_rsa",
		},
		{
			"resources_read_windows_forward_slash",
			"resources/read",
			`{"uri":"C:/Users/me/.ssh/id_rsa"}`,
			"read_file", "path", "C:/Users/me/.ssh/id_rsa",
		},
		{
			"resources_read_file_uri_windows",
			"resources/read",
			`{"uri":"file:///C:/Users/me/.ssh/id_rsa"}`,
			"read_file", "path", "C:/Users/me/.ssh/id_rsa",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc, err := MCPMethodToToolCall(tt.method, json.RawMessage(tt.params))
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

func TestMcpMethodToToolCall_EmptyArguments(t *testing.T) {
	tc, err := MCPMethodToToolCall("tools/call", json.RawMessage(`{"name":"ping"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc == nil {
		t.Fatal("expected non-nil ToolCall")
		return
	}
	if tc.Name != "ping" {
		t.Errorf("name = %s, want ping", tc.Name)
	}
	if string(tc.Arguments) != "{}" {
		t.Errorf("arguments = %s, want {}", string(tc.Arguments))
	}
}

func TestMcpMethodToToolCall_Unknown(t *testing.T) {
	for _, method := range []string{"initialize", "tools/list", "prompts/get", "notifications/cancelled"} { //nolint:misspell // MCP protocol uses "cancelled"
		tc, err := MCPMethodToToolCall(method, nil)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", method, err)
		}
		if tc != nil {
			t.Errorf("%s should not be security-relevant", method)
		}
	}
}

func TestMcpMethodToToolCall_SamplingCreateMessage(t *testing.T) {
	params := `{"messages":[{"role":"user","content":{"type":"text","text":"hello"}}],"maxTokens":100}`
	tc, err := MCPMethodToToolCall("sampling/createMessage", json.RawMessage(params))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc == nil {
		t.Fatal("expected non-nil ToolCall")
		return
	}
	if tc.Name != "mcp_sampling" {
		t.Errorf("name = %s, want mcp_sampling", tc.Name)
	}
	// Full params should be passed as Arguments for DLP inspection.
	if string(tc.Arguments) != params {
		t.Errorf("arguments = %s, want %s", string(tc.Arguments), params)
	}
}

func TestMcpMethodToToolCall_ElicitationCreate(t *testing.T) {
	params := `{"message":"Please enter your API key","schema":{"type":"object"}}`
	tc, err := MCPMethodToToolCall("elicitation/create", json.RawMessage(params))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc == nil {
		t.Fatal("expected non-nil ToolCall")
		return
	}
	if tc.Name != "mcp_elicitation" {
		t.Errorf("name = %s, want mcp_elicitation", tc.Name)
	}
	if string(tc.Arguments) != params {
		t.Errorf("arguments = %s, want %s", string(tc.Arguments), params)
	}
}

func TestMcpMethodToToolCall_SamplingNilParams(t *testing.T) {
	for _, input := range []json.RawMessage{nil, json.RawMessage(`null`), json.RawMessage(``)} {
		tc, err := MCPMethodToToolCall("sampling/createMessage", input)
		if tc != nil {
			t.Errorf("expected nil ToolCall for nil/null params, got %+v", tc)
		}
		if err == nil {
			t.Error("expected error for nil/null params on security method")
		}
	}
}

func TestMcpMethodToToolCall_ElicitationEmptyMessage(t *testing.T) {
	tc, err := MCPMethodToToolCall("elicitation/create", json.RawMessage(`{"message":""}`))
	if tc != nil {
		t.Error("expected nil ToolCall for empty message")
	}
	if err == nil {
		t.Error("expected error for empty message in elicitation/create")
	}
}

func TestMcpMethodToToolCall_MalformedParams(t *testing.T) {
	methods := []string{"tools/call", "resources/read", "sampling/createMessage", "elicitation/create"}
	badInputs := []json.RawMessage{
		json.RawMessage(`{broken`),
		json.RawMessage(`"just a string"`),
		json.RawMessage(`null`),
		json.RawMessage(`42`),
		json.RawMessage(``),
	}
	for _, method := range methods {
		for _, input := range badInputs {
			tc, err := MCPMethodToToolCall(method, input)
			if tc != nil {
				t.Errorf("%s with %q: expected nil ToolCall for malformed params", method, input)
			}
			if err == nil {
				t.Errorf("%s with %q: expected error for malformed params", method, input)
			}
		}
	}
}

func TestMcpMethodToToolCall_EmptyName(t *testing.T) {
	tc, err := MCPMethodToToolCall("tools/call", json.RawMessage(`{"name":"","arguments":{}}`))
	if tc != nil {
		t.Error("expected nil ToolCall for empty name")
	}
	if err == nil {
		t.Error("expected error for empty tool name")
	}
}

func TestMcpMethodToToolCall_EmptyURI(t *testing.T) {
	tc, err := MCPMethodToToolCall("resources/read", json.RawMessage(`{"uri":""}`))
	if tc != nil {
		t.Error("expected nil ToolCall for empty URI")
	}
	if err == nil {
		t.Error("expected error for empty URI")
	}
}
