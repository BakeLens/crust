package autowrap

import (
	"encoding/json"
	"strings"
	"testing"
)

// --- MCP methods detected first ---

func TestBothMethodToToolCall_MCP_ToolsCall(t *testing.T) {
	params := json.RawMessage(`{"name":"read_file","arguments":{"path":"/etc/passwd"}}`)
	tc, err := BothMethodToToolCall("tools/call", params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc == nil {
		t.Fatal("expected non-nil ToolCall for tools/call")
	}
	if tc.Name != "read_file" {
		t.Errorf("Name = %q, want %q", tc.Name, "read_file")
	}
}

func TestBothMethodToToolCall_MCP_ResourcesRead(t *testing.T) {
	params := json.RawMessage(`{"uri":"/home/user/secrets.txt"}`)
	tc, err := BothMethodToToolCall("resources/read", params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc == nil {
		t.Fatal("expected non-nil ToolCall for resources/read")
	}
	if tc.Name != "read_file" {
		t.Errorf("Name = %q, want %q", tc.Name, "read_file")
	}
}

func TestBothMethodToToolCall_MCP_SamplingCreateMessage(t *testing.T) {
	params := json.RawMessage(`{"messages":[{"role":"user","content":"hello"}],"maxTokens":100}`)
	tc, err := BothMethodToToolCall("sampling/createMessage", params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc == nil {
		t.Fatal("expected non-nil ToolCall for sampling/createMessage")
	}
	if tc.Name != "mcp_sampling" {
		t.Errorf("Name = %q, want %q", tc.Name, "mcp_sampling")
	}
}

// --- ACP methods detected second (fallback path) ---

func TestBothMethodToToolCall_ACP_FsReadTextFile(t *testing.T) {
	params := json.RawMessage(`{"sessionId":"s1","path":"/app/.env"}`)
	tc, err := BothMethodToToolCall("fs/read_text_file", params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc == nil {
		t.Fatal("expected non-nil ToolCall for fs/read_text_file")
	}
	if tc.Name != "read_file" {
		t.Errorf("Name = %q, want %q", tc.Name, "read_file")
	}
	// Verify the path is preserved in arguments.
	var args map[string]string
	if err := json.Unmarshal(tc.Arguments, &args); err != nil {
		t.Fatalf("unmarshal args: %v", err)
	}
	if args["path"] != "/app/.env" {
		t.Errorf("path = %q, want %q", args["path"], "/app/.env")
	}
}

func TestBothMethodToToolCall_ACP_FsWriteTextFile(t *testing.T) {
	params := json.RawMessage(`{"sessionId":"s1","path":"/tmp/out.txt","content":"pwned"}`)
	tc, err := BothMethodToToolCall("fs/write_text_file", params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc == nil {
		t.Fatal("expected non-nil ToolCall for fs/write_text_file")
	}
	if tc.Name != "write_file" {
		t.Errorf("Name = %q, want %q", tc.Name, "write_file")
	}
}

func TestBothMethodToToolCall_ACP_TerminalCreate(t *testing.T) {
	params := json.RawMessage(`{"sessionId":"s1","command":"ls","args":["-la"]}`)
	tc, err := BothMethodToToolCall("terminal/create", params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc == nil {
		t.Fatal("expected non-nil ToolCall for terminal/create")
	}
	if tc.Name != "bash" {
		t.Errorf("Name = %q, want %q", tc.Name, "bash")
	}
}

// --- Non-security methods return (nil, nil) ---

func TestBothMethodToToolCall_NonSecurityMethod(t *testing.T) {
	methods := []string{
		"notifications/initialized",
		"ping",
		"$/cancelRequest",
		"textDocument/didOpen",
		"initialize",
		"completion/complete",
		"prompts/get",
	}
	for _, m := range methods {
		tc, err := BothMethodToToolCall(m, json.RawMessage(`{}`))
		if tc != nil {
			t.Errorf("method %q: expected nil ToolCall, got %+v", m, tc)
		}
		if err != nil {
			t.Errorf("method %q: expected nil error, got %v", m, err)
		}
	}
}

// --- Malformed params for security methods return error ---

func TestBothMethodToToolCall_MalformedParams_MCP(t *testing.T) {
	cases := []struct {
		method string
		params string
	}{
		{"tools/call", `{not json`},
		{"resources/read", `{not json`},
		{"sampling/createMessage", `{not json`},
	}
	for _, c := range cases {
		tc, err := BothMethodToToolCall(c.method, json.RawMessage(c.params))
		if err == nil {
			t.Errorf("method %q: expected error for malformed params, got nil", c.method)
		}
		if tc != nil {
			t.Errorf("method %q: expected nil ToolCall for malformed params, got %+v", c.method, tc)
		}
	}
}

func TestBothMethodToToolCall_MalformedParams_ACP(t *testing.T) {
	cases := []struct {
		method string
		params string
	}{
		{"fs/read_text_file", `{not json`},
		{"fs/write_text_file", `{not json`},
		{"terminal/create", `{not json`},
	}
	for _, c := range cases {
		tc, err := BothMethodToToolCall(c.method, json.RawMessage(c.params))
		if err == nil {
			t.Errorf("method %q: expected error for malformed params, got nil", c.method)
		}
		if tc != nil {
			t.Errorf("method %q: expected nil ToolCall for malformed params, got %+v", c.method, tc)
		}
	}
}

// --- Nil/null params for security methods return error ---

func TestBothMethodToToolCall_NilParams_MCP(t *testing.T) {
	methods := []string{"tools/call", "resources/read", "sampling/createMessage"}
	for _, m := range methods {
		// nil params
		tc, err := BothMethodToToolCall(m, nil)
		if err == nil {
			t.Errorf("method %q nil params: expected error, got nil", m)
		}
		if tc != nil {
			t.Errorf("method %q nil params: expected nil ToolCall, got %+v", m, tc)
		}

		// "null" params
		tc, err = BothMethodToToolCall(m, json.RawMessage("null"))
		if err == nil {
			t.Errorf("method %q null params: expected error, got nil", m)
		}
		if tc != nil {
			t.Errorf("method %q null params: expected nil ToolCall, got %+v", m, tc)
		}
	}
}

func TestBothMethodToToolCall_NilParams_ACP(t *testing.T) {
	methods := []string{"fs/read_text_file", "fs/write_text_file", "terminal/create"}
	for _, m := range methods {
		// nil params
		tc, err := BothMethodToToolCall(m, nil)
		if err == nil {
			t.Errorf("method %q nil params: expected error, got nil", m)
		}
		if tc != nil {
			t.Errorf("method %q nil params: expected nil ToolCall, got %+v", m, tc)
		}

		// "null" params
		tc, err = BothMethodToToolCall(m, json.RawMessage("null"))
		if err == nil {
			t.Errorf("method %q null params: expected error, got nil", m)
		}
		if tc != nil {
			t.Errorf("method %q null params: expected nil ToolCall, got %+v", m, tc)
		}
	}
}

// --- MCP takes priority over ACP (method names are disjoint, verify no overlap) ---

func TestBothMethodToToolCall_MCPPriorityOverACP(t *testing.T) {
	// Verify that MCP method names and ACP method names don't overlap.
	// If they did, MCP would win since it's checked first.
	mcpMethods := []string{"tools/call", "resources/read", "sampling/createMessage", "elicitation/create"}
	acpMethods := []string{"fs/read_text_file", "fs/write_text_file", "terminal/create"}

	mcpSet := make(map[string]bool, len(mcpMethods))
	for _, m := range mcpMethods {
		mcpSet[m] = true
	}
	for _, m := range acpMethods {
		if mcpSet[m] {
			t.Errorf("method %q exists in both MCP and ACP — MCP would shadow ACP", m)
		}
	}

	// Also verify that each ACP method actually reaches the ACP converter
	// (i.e., the MCP converter returns nil,nil for these).
	for _, m := range acpMethods {
		params := json.RawMessage(`{"sessionId":"s1","path":"/tmp/test","command":"echo","content":"x"}`)
		tc, err := BothMethodToToolCall(m, params)
		if err != nil {
			t.Fatalf("ACP method %q: unexpected error: %v", m, err)
		}
		if tc == nil {
			t.Errorf("ACP method %q: expected non-nil ToolCall (should reach ACP converter)", m)
		}
	}
}

// --- Verify ToolCall fields in detail ---

func TestBothMethodToToolCall_ToolsCall_ArgumentsPreserved(t *testing.T) {
	params := json.RawMessage(`{"name":"execute","arguments":{"cmd":"rm -rf /","flag":true}}`)
	tc, err := BothMethodToToolCall("tools/call", params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc == nil {
		t.Fatal("expected non-nil ToolCall")
	}
	// The arguments should be preserved from the original params.
	var args map[string]any
	if err := json.Unmarshal(tc.Arguments, &args); err != nil {
		t.Fatalf("unmarshal args: %v", err)
	}
	if args["cmd"] != "rm -rf /" {
		t.Errorf("cmd = %q, want %q", args["cmd"], "rm -rf /")
	}
}

func TestBothMethodToToolCall_ToolsCall_EmptyName(t *testing.T) {
	params := json.RawMessage(`{"name":"","arguments":{}}`)
	tc, err := BothMethodToToolCall("tools/call", params)
	if err == nil {
		t.Error("expected error for empty tool name")
	}
	if tc != nil {
		t.Errorf("expected nil ToolCall, got %+v", tc)
	}
}

func TestBothMethodToToolCall_ToolsCall_NoArguments(t *testing.T) {
	// tools/call with name but no arguments field — should default to {}
	params := json.RawMessage(`{"name":"my_tool"}`)
	tc, err := BothMethodToToolCall("tools/call", params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc == nil {
		t.Fatal("expected non-nil ToolCall")
	}
	if string(tc.Arguments) != "{}" {
		t.Errorf("Arguments = %s, want {}", string(tc.Arguments))
	}
}

func TestBothMethodToToolCall_ResourcesRead_HTTPUri(t *testing.T) {
	params := json.RawMessage(`{"uri":"https://evil.com/exfil"}`)
	tc, err := BothMethodToToolCall("resources/read", params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc == nil {
		t.Fatal("expected non-nil ToolCall")
	}
	if tc.Name != "mcp_resource_read" {
		t.Errorf("Name = %q, want %q", tc.Name, "mcp_resource_read")
	}
	var args map[string]string
	if err := json.Unmarshal(tc.Arguments, &args); err != nil {
		t.Fatalf("unmarshal args: %v", err)
	}
	if args["url"] != "https://evil.com/exfil" {
		t.Errorf("url = %q, want %q", args["url"], "https://evil.com/exfil")
	}
}

func TestBothMethodToToolCall_ResourcesRead_EmptyURI(t *testing.T) {
	params := json.RawMessage(`{"uri":""}`)
	tc, err := BothMethodToToolCall("resources/read", params)
	if err == nil {
		t.Error("expected error for empty URI")
	}
	if tc != nil {
		t.Errorf("expected nil ToolCall, got %+v", tc)
	}
}

func TestBothMethodToToolCall_ResourcesRead_FileURI(t *testing.T) {
	params := json.RawMessage(`{"uri":"file:///etc/shadow"}`)
	tc, err := BothMethodToToolCall("resources/read", params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc == nil {
		t.Fatal("expected non-nil ToolCall")
	}
	if tc.Name != "read_file" {
		t.Errorf("Name = %q, want %q", tc.Name, "read_file")
	}
}

func TestBothMethodToToolCall_ElicitationCreate(t *testing.T) {
	params := json.RawMessage(`{"message":"Click here to verify your identity"}`)
	tc, err := BothMethodToToolCall("elicitation/create", params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc == nil {
		t.Fatal("expected non-nil ToolCall")
	}
	if tc.Name != "mcp_elicitation" {
		t.Errorf("Name = %q, want %q", tc.Name, "mcp_elicitation")
	}
}

func TestBothMethodToToolCall_ElicitationCreate_EmptyMessage(t *testing.T) {
	params := json.RawMessage(`{"message":""}`)
	tc, err := BothMethodToToolCall("elicitation/create", params)
	if err == nil {
		t.Error("expected error for empty message")
	}
	if tc != nil {
		t.Errorf("expected nil ToolCall, got %+v", tc)
	}
}

func TestBothMethodToToolCall_ACP_TerminalCreate_EmptyCommand(t *testing.T) {
	params := json.RawMessage(`{"sessionId":"s1","command":""}`)
	tc, err := BothMethodToToolCall("terminal/create", params)
	if err == nil {
		t.Error("expected error for empty command")
	}
	if tc != nil {
		t.Errorf("expected nil ToolCall, got %+v", tc)
	}
}

// --- Verify return type contract ---

func TestBothMethodToToolCall_ContractPassthrough(t *testing.T) {
	// Non-security methods: both returns must be nil.
	tc, err := BothMethodToToolCall("notifications/progress", json.RawMessage(`{"token":"abc"}`))
	if tc != nil || err != nil {
		t.Errorf("non-security method: expected (nil, nil), got (%v, %v)", tc, err)
	}
}

func TestBothMethodToToolCall_ContractSuccess(t *testing.T) {
	// Security method with valid params: tc != nil, err == nil.
	tc, err := BothMethodToToolCall("tools/call", json.RawMessage(`{"name":"test","arguments":{}}`))
	if tc == nil || err != nil {
		t.Fatalf("valid security method: expected (tc, nil), got (%v, %v)", tc, err)
	}
	if tc.Name != "test" {
		t.Errorf("Name = %q, want %q", tc.Name, "test")
	}
}

func TestBothMethodToToolCall_ContractError(t *testing.T) {
	// Security method with bad params: tc == nil, err != nil.
	tc, err := BothMethodToToolCall("tools/call", json.RawMessage(`{bad`))
	if tc != nil || err == nil {
		t.Errorf("malformed security method: expected (nil, err), got (%v, %v)", tc, err)
	}
}

// --- Verify error messages contain method name ---

func TestBothMethodToToolCall_ErrorMessageContainsMethod(t *testing.T) {
	cases := []struct {
		method string
		params json.RawMessage
	}{
		{"tools/call", nil},
		{"resources/read", nil},
		{"sampling/createMessage", nil},
		{"fs/read_text_file", nil},
		{"fs/write_text_file", nil},
		{"terminal/create", nil},
		{"tools/call", json.RawMessage(`{bad}`)},
		{"resources/read", json.RawMessage(`{bad}`)},
	}
	for _, c := range cases {
		_, err := BothMethodToToolCall(c.method, c.params)
		if err == nil {
			t.Errorf("method %q: expected error", c.method)
			continue
		}
		if !strings.Contains(err.Error(), c.method) {
			t.Errorf("method %q: error %q should contain method name", c.method, err.Error())
		}
	}
}

// --- Verify return is a proper *rules.ToolCall ---

func TestBothMethodToToolCall_ReturnType(t *testing.T) {
	tc, err := BothMethodToToolCall("fs/read_text_file", json.RawMessage(`{"sessionId":"s1","path":"/tmp/x"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc == nil {
		t.Fatal("expected non-nil")
	}
}
