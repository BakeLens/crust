package jsonrpc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/testutil"
)

// dlpConverter returns nil, nil for everything (passthrough) — DLP scanning
// is independent of the method converter.
func dlpConverter(_ string, _ json.RawMessage) (*rules.ToolCall, error) {
	return nil, nil
}

// fakeAWSKey builds a string that matches the AWS access key DLP pattern
// at runtime, avoiding Crust's own DLP from blocking file writes.
func fakeAWSKey() string {
	return "AKIA" + "IOSFODNN7EXAMPLE"
}

// fakeGitHubToken builds a string that matches the GitHub token DLP pattern.
func fakeGitHubToken() string {
	return "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm"
}

// runInspectDLP runs PipeInspect and returns the forward and error output.
func runInspectDLP(t *testing.T, input string) (fwd, errOut string) {
	t.Helper()
	engine := testutil.NewEngine(t)
	var fwdBuf, errBuf bytes.Buffer
	fwdWriter := NewLockedWriter(&fwdBuf)
	errWriter := NewLockedWriter(&errBuf)
	PipeInspect(logger.New("test"), engine, strings.NewReader(input),
		fwdWriter, errWriter, dlpConverter, "TEST", "test-label")
	return fwdBuf.String(), errBuf.String()
}

// TestResponseDLP_ErrorGoesToErrWriter verifies that when DLP blocks a
// response (server → client), the JSON-RPC error is sent to errWriter
// (back to the client), NOT to fwdWriter (toward the server).
//
// This is a regression test for a bug where scanDLP was called with
// fwdWriter instead of errWriter for response DLP scanning.
func TestResponseDLP_ErrorGoesToErrWriter(t *testing.T) {
	// A response containing an AWS access key — should be blocked by DLP.
	msg := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":{"key":"%s"}}`, fakeAWSKey()) + "\n"
	fwd, errOut := runInspectDLP(t, msg)

	// The response must NOT be forwarded (contains leaked secret).
	if strings.Contains(fwd, "AKIA") {
		t.Errorf("DLP-blocked response was forwarded (leaked secret passed through):\n  fwd: %s", fwd)
	}

	// The error response must appear on errWriter (back to client), not fwdWriter.
	if errOut == "" {
		t.Error("DLP block error was not sent to errWriter — client would see silence/timeout")
	}
	if strings.Contains(fwd, `"error"`) {
		t.Error("DLP block error was sent to fwdWriter (toward server) instead of errWriter (toward client)")
	}

	// Verify the error response is valid JSON-RPC.
	if errOut != "" {
		var resp ErrorResponse
		if err := json.Unmarshal(bytes.TrimSpace([]byte(errOut)), &resp); err != nil {
			t.Fatalf("error response is not valid JSON-RPC: %v\n  raw: %s", err, errOut)
		}
		if resp.Error.Code != BlockedError {
			t.Errorf("error code = %d, want %d", resp.Error.Code, BlockedError)
		}
	}
}

// TestResponseDLP_CleanResponsePassesThrough verifies that responses
// without secrets are forwarded normally.
func TestResponseDLP_CleanResponsePassesThrough(t *testing.T) {
	msg := `{"jsonrpc":"2.0","id":1,"result":{"data":"safe content"}}` + "\n"
	fwd, errOut := runInspectDLP(t, msg)

	if fwd != msg {
		t.Errorf("clean response should pass through, got:\n  fwd: %q", fwd)
	}
	if errOut != "" {
		t.Errorf("unexpected error for clean response: %s", errOut)
	}
}

// TestResponseDLP_ErrorFieldBlocked verifies DLP scanning of the error
// field in JSON-RPC error responses (not just the result field).
func TestResponseDLP_ErrorFieldBlocked(t *testing.T) {
	// An error response where the error message contains a GitHub token.
	msg := fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"error":{"code":-1,"message":"auth failed: %s"}}`, fakeGitHubToken()) + "\n"
	fwd, errOut := runInspectDLP(t, msg)

	if strings.Contains(fwd, "ghp_") {
		t.Errorf("DLP-blocked error response was forwarded:\n  fwd: %s", fwd)
	}
	if errOut == "" {
		t.Error("DLP block error for error-field leak was not sent to errWriter")
	}
}

// TestNotificationDLP_NoErrorResponse verifies that DLP-blocked
// notifications do not generate error responses (notifications have no ID).
func TestNotificationDLP_NoErrorResponse(t *testing.T) {
	msg := fmt.Sprintf(`{"jsonrpc":"2.0","method":"update","params":{"secret":"%s"}}`, fakeAWSKey()) + "\n"
	fwd, errOut := runInspectDLP(t, msg)

	if strings.Contains(fwd, "AKIA") {
		t.Errorf("DLP-blocked notification was forwarded:\n  fwd: %s", fwd)
	}
	// Notifications have no ID — no error response should be sent.
	if errOut != "" {
		t.Errorf("error response sent for notification (has no ID to reply to): %s", errOut)
	}
}
