package acpwrap

import (
	"bytes"
	"strings"
	"testing"

	"github.com/BakeLens/crust/internal/jsonrpc"
	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/testutil"
)

var testLog = logger.New("acp-test")

// runPipe runs PipeInspect with ACPMethodToToolCall and returns what was
// forwarded and what error responses were generated.
func runPipe(t *testing.T, input string) (fwd, errOut string) {
	t.Helper()
	engine := testutil.NewEngine(t)
	var fwdBuf, errBuf bytes.Buffer
	fwdWriter := jsonrpc.NewLockedWriter(&fwdBuf)
	errWriter := jsonrpc.NewLockedWriter(&errBuf)
	jsonrpc.PipeInspect(testLog, engine, strings.NewReader(input),
		fwdWriter, errWriter, ACPMethodToToolCall, "ACP", "Agent->IDE", nil)
	return fwdBuf.String(), errBuf.String()
}

// --- ACPMethodToToolCall converter edge cases ---
// Path-based blocking (.env, .ssh) and passthrough are covered by
// jsonrpc/proxy_test.go (unit) and mcpgateway/e2e_test.go (E2E).
// These tests verify ACP-specific converter error handling.

func TestPipeAgentToIDE_BlocksConverterEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		msg  string
	}{
		{"malformed_read_params", `{"jsonrpc":"2.0","id":4,"method":"fs/read_text_file","params":"not-an-object"}`},
		{"malformed_terminal_params", `{"jsonrpc":"2.0","id":5,"method":"terminal/create","params":42}`},
		{"null_params", `{"jsonrpc":"2.0","id":6,"method":"fs/read_text_file","params":null}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fwd, errOut := runPipe(t, tt.msg+"\n")
			if fwd != "" {
				t.Errorf("IDE should not receive blocked request, got: %s", fwd)
			}
			if errOut == "" {
				t.Error("agent should receive an error response")
			}
		})
	}
}
