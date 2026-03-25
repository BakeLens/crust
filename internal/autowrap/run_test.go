package autowrap

import (
	"bytes"
	"strings"
	"testing"

	"github.com/BakeLens/crust/internal/jsonrpc"
	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/mcpgateway"
	"github.com/BakeLens/crust/internal/testutil"
)

var testLog = logger.New("wrap-test")

// runInboundPipe runs PipeInspect with MCPMethodToToolCall (inbound direction).
func runInboundPipe(t *testing.T, input string) (fwd, errOut string) {
	t.Helper()
	engine := testutil.NewEngine(t)
	var fwdBuf, errBuf bytes.Buffer
	fwdWriter := jsonrpc.NewLockedWriter(&fwdBuf)
	errWriter := jsonrpc.NewLockedWriter(&errBuf)
	jsonrpc.PipeInspect(testLog, engine, strings.NewReader(input),
		fwdWriter, errWriter, mcpgateway.MCPMethodToToolCall, "MCP", "Inbound", nil)
	return fwdBuf.String(), errBuf.String()
}

// runOutboundPipe runs PipeInspect with BothMethodToToolCall (outbound direction).
func runOutboundPipe(t *testing.T, input string) (fwd, errOut string) {
	t.Helper()
	engine := testutil.NewEngine(t)
	var fwdBuf, errBuf bytes.Buffer
	fwdWriter := jsonrpc.NewLockedWriter(&fwdBuf)
	errWriter := jsonrpc.NewLockedWriter(&errBuf)
	jsonrpc.PipeInspect(testLog, engine, strings.NewReader(input),
		fwdWriter, errWriter, BothMethodToToolCall, "Stdio", "Outbound", nil)
	return fwdBuf.String(), errBuf.String()
}

// --- Cross-protocol tests ---
// These are unique to autowrap: they verify that the inbound MCP converter
// ignores ACP methods, and the outbound BothMethodToToolCall catches both.

func TestPipeInbound_IgnoresACPMethods(t *testing.T) {
	// Inbound uses MCPMethodToToolCall only — ACP methods pass through unexamined.
	msg := `{"jsonrpc":"2.0","id":1,"method":"fs/read_text_file","params":{"sessionId":"s1","path":"/app/.env"}}`
	fwd, errOut := runInboundPipe(t, msg+"\n")
	if fwd != msg+"\n" {
		t.Errorf("ACP methods should pass through in inbound direction\ngot:  %q\nwant: %q", fwd, msg+"\n")
	}
	if errOut != "" {
		t.Errorf("should not generate errors for ACP methods in inbound direction, got: %s", errOut)
	}
}

func TestPipeOutbound_BlocksMCPMethods(t *testing.T) {
	// Outbound uses BothMethodToToolCall — MCP methods with sensitive paths are blocked.
	msg := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/app/.env"}}}`
	fwd, errOut := runOutboundPipe(t, msg+"\n")
	if fwd != "" {
		t.Errorf("MCP methods with .env should be blocked on outbound, got forwarded: %s", fwd)
	}
	if errOut == "" {
		t.Error("subprocess should receive an error response for blocked MCP method")
	}
}
