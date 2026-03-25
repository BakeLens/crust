package jsonrpc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/testutil"
)

var testLog = logger.New("test")

// blockAllConverter is a test converter that treats "security/call" as security-relevant
// and maps it to a tool call that will be blocked by the built-in rules.
func blockAllConverter(method string, params json.RawMessage) (*rules.ToolCall, error) {
	if method == "security/call" {
		args, _ := json.Marshal(map[string]string{"path": "/etc/shadow"})
		return &rules.ToolCall{Name: "read_file", Arguments: args}, nil
	}
	if method == "malformed/call" {
		return nil, fmt.Errorf("malformed params")
	}
	return nil, nil // not security-relevant
}

// passthroughConverter returns nil, nil for everything (all passthrough).
func passthroughConverter(method string, params json.RawMessage) (*rules.ToolCall, error) {
	return nil, nil
}

// --- WriteLine ---

func TestWriteLine(t *testing.T) {
	t.Run("does_not_mutate_input", func(t *testing.T) {
		var buf bytes.Buffer
		lw := NewLockedWriter(&buf)

		backing := make([]byte, 6, 100)
		copy(backing, "helloX")
		data := backing[:5]

		if err := lw.WriteLine(data); err != nil {
			t.Fatal(err)
		}
		if backing[5] != 'X' {
			t.Errorf("WriteLine mutated caller's buffer: byte after data is %q, want 'X'", backing[5])
		}
		if buf.String() != "hello\n" {
			t.Errorf("output = %q, want %q", buf.String(), "hello\n")
		}
	})

	t.Run("consecutive_writes", func(t *testing.T) {
		var buf bytes.Buffer
		lw := NewLockedWriter(&buf)

		for _, line := range []string{"first", "second", "third"} {
			if err := lw.WriteLine([]byte(line)); err != nil {
				t.Fatal(err)
			}
		}
		if got, want := buf.String(), "first\nsecond\nthird\n"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

// --- SendBlockError ---

func TestSendBlockError(t *testing.T) {
	var buf bytes.Buffer
	lw := NewLockedWriter(&buf)
	SendBlockError(testLog, lw, json.RawMessage(`1`), "test error")

	var resp ErrorResponse
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &resp); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}
	if resp.JSONRPC != "2.0" {
		t.Errorf("jsonrpc = %q, want %q", resp.JSONRPC, "2.0")
	}
	if resp.Error.Code != BlockedError {
		t.Errorf("error code = %d, want %d", resp.Error.Code, BlockedError)
	}
	if resp.Error.Message != "test error" {
		t.Errorf("error message = %q, want %q", resp.Error.Message, "test error")
	}
}

// --- PipePassthrough ---

func TestPipePassthrough(t *testing.T) {
	input := "line1\nline2\nline3\n"
	var buf bytes.Buffer
	dst := NewLockedWriter(&buf)
	PipePassthrough(testLog, strings.NewReader(input), dst, "test")

	if got := buf.String(); got != input {
		t.Errorf("got %q, want %q", got, input)
	}
}

func TestPipePassthrough_EmptyInput(t *testing.T) {
	var buf bytes.Buffer
	dst := NewLockedWriter(&buf)
	PipePassthrough(testLog, strings.NewReader(""), dst, "test")

	if buf.Len() != 0 {
		t.Errorf("expected empty output, got %q", buf.String())
	}
}

// --- PipeInspect ---

func runInspect(t *testing.T, input string, convert MethodConverter) (fwd, errOut string) {
	t.Helper()
	engine := testutil.NewEngine(t)
	var fwdBuf, errBuf bytes.Buffer
	fwdWriter := NewLockedWriter(&fwdBuf)
	errWriter := NewLockedWriter(&errBuf)
	PipeInspect(testLog, engine, strings.NewReader(input),
		fwdWriter, errWriter, convert, "TEST", "test-label", nil)
	return fwdBuf.String(), errBuf.String()
}

func TestPipeInspect_PassesNonSecurityRequest(t *testing.T) {
	msg := `{"jsonrpc":"2.0","id":1,"method":"other/call","params":{}}` + "\n"
	fwd, errOut := runInspect(t, msg, blockAllConverter)
	if fwd != msg {
		t.Errorf("expected passthrough, got %q", fwd)
	}
	if errOut != "" {
		t.Errorf("unexpected error response: %s", errOut)
	}
}

func TestPipeInspect_PassesNotification(t *testing.T) {
	msg := `{"jsonrpc":"2.0","method":"update","params":{}}` + "\n"
	fwd, errOut := runInspect(t, msg, blockAllConverter)
	if fwd != msg {
		t.Errorf("expected passthrough, got %q", fwd)
	}
	if errOut != "" {
		t.Errorf("unexpected error response: %s", errOut)
	}
}

func TestPipeInspect_PassesResponse(t *testing.T) {
	msg := `{"jsonrpc":"2.0","id":1,"result":{"data":"ok"}}` + "\n"
	fwd, errOut := runInspect(t, msg, blockAllConverter)
	if fwd != msg {
		t.Errorf("expected passthrough, got %q", fwd)
	}
	if errOut != "" {
		t.Errorf("unexpected error response: %s", errOut)
	}
}

func TestPipeInspect_PassesInvalidJSON(t *testing.T) {
	msg := "not valid json\n"
	fwd, errOut := runInspect(t, msg, blockAllConverter)
	if fwd != msg {
		t.Errorf("expected passthrough, got %q", fwd)
	}
	if errOut != "" {
		t.Errorf("unexpected error response: %s", errOut)
	}
}

func TestPipeInspect_PassesEmptyLine(t *testing.T) {
	fwd, _ := runInspect(t, "\n", blockAllConverter)
	if fwd != "\n" {
		t.Errorf("empty line should pass through, got %q", fwd)
	}
}

func TestPipeInspect_BlocksSecurityRequest(t *testing.T) {
	msg := `{"jsonrpc":"2.0","id":1,"method":"security/call","params":{}}` + "\n"
	fwd, errOut := runInspect(t, msg, blockAllConverter)
	if fwd != "" {
		t.Errorf("blocked request should not be forwarded, got %q", fwd)
	}
	if errOut == "" {
		t.Error("expected error response for blocked request")
	}
	var resp ErrorResponse
	if err := json.Unmarshal(bytes.TrimSpace([]byte(errOut)), &resp); err != nil {
		t.Fatalf("failed to parse error: %v", err)
	}
	if resp.Error.Code != BlockedError {
		t.Errorf("error code = %d, want %d", resp.Error.Code, BlockedError)
	}
	if !strings.Contains(resp.Error.Message, "[Crust]") {
		t.Errorf("error message should contain [Crust]: %s", resp.Error.Message)
	}
}

func TestPipeInspect_BlocksMalformedParams(t *testing.T) {
	msg := `{"jsonrpc":"2.0","id":1,"method":"malformed/call","params":{}}` + "\n"
	fwd, errOut := runInspect(t, msg, blockAllConverter)
	if fwd != "" {
		t.Errorf("malformed request should not be forwarded, got %q", fwd)
	}
	if errOut == "" {
		t.Error("expected error response for malformed params")
	}
}

func TestPipeInspect_MultipleMessages(t *testing.T) {
	msgs := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"security/call","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"other/call","params":{}}`,
		`{"jsonrpc":"2.0","id":3,"method":"malformed/call","params":{}}`,
	}, "\n") + "\n"

	fwd, errOut := runInspect(t, msgs, blockAllConverter)

	fwdLines := strings.Split(strings.TrimRight(fwd, "\n"), "\n")
	if len(fwdLines) != 1 {
		t.Errorf("expected 1 forwarded message, got %d: %v", len(fwdLines), fwdLines)
	}

	errLines := strings.Split(strings.TrimRight(errOut, "\n"), "\n")
	if len(errLines) != 2 {
		t.Errorf("expected 2 error responses (blocked + malformed), got %d: %v", len(errLines), errLines)
	}
}

// --- RunProxy ---

func TestRunProxy_NoHang(t *testing.T) {
	if _, err := exec.LookPath("true"); err != nil {
		t.Skip("'true' not found in PATH")
	}
	engine := testutil.NewEngine(t)
	stdinR, stdinW := io.Pipe()
	defer stdinW.Close() // keep write end OPEN to expose the hang bug

	done := make(chan int, 1)
	go func() {
		done <- RunProxy(engine, []string{"true"}, stdinR, &bytes.Buffer{}, ProxyConfig{
			Log:          testLog,
			ProcessLabel: "test-true",
			Inbound:      PipeConfig{Label: "in"},
			Outbound:     PipeConfig{Label: "out"},
		})
	}()

	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit code = %d, want 0", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunProxy hung — stdin not closed after child exit")
	}
}

func TestRunProxy_ExitCode(t *testing.T) {
	if _, err := exec.LookPath("false"); err != nil {
		t.Skip("'false' not found in PATH")
	}
	engine := testutil.NewEngine(t)
	stdinR, stdinW := io.Pipe()
	defer stdinW.Close()

	done := make(chan int, 1)
	go func() {
		done <- RunProxy(engine, []string{"false"}, stdinR, &bytes.Buffer{}, ProxyConfig{
			Log:          testLog,
			ProcessLabel: "test-false",
			Inbound:      PipeConfig{Label: "in"},
			Outbound:     PipeConfig{Label: "out"},
		})
	}()

	select {
	case code := <-done:
		if code == 0 {
			t.Error("expected non-zero exit code from 'false'")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunProxy hung")
	}
}

func TestRunProxy_WithInspect(t *testing.T) {
	if _, err := exec.LookPath("cat"); err != nil {
		t.Skip("'cat' not found in PATH")
	}
	engine := testutil.NewEngine(t)

	// cat echoes stdin to stdout — so we send a message and check it comes through
	input := `{"jsonrpc":"2.0","id":1,"method":"other/call","params":{}}` + "\n"
	stdinR := io.NopCloser(strings.NewReader(input))
	var stdout bytes.Buffer

	done := make(chan int, 1)
	go func() {
		done <- RunProxy(engine, []string{"cat"}, stdinR, &stdout, ProxyConfig{
			Log:          testLog,
			ProcessLabel: "test-cat",
			Inbound:      PipeConfig{Label: "in", Protocol: "TEST", Convert: passthroughConverter},
			Outbound:     PipeConfig{Label: "out", Protocol: "TEST", Convert: passthroughConverter},
		})
	}()

	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit code = %d, want 0", code)
		}
		if !strings.Contains(stdout.String(), "other/call") {
			t.Errorf("expected message to pass through cat, got %q", stdout.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunProxy hung")
	}
}

// --- Signal helpers ---

func TestForwardSignals_StopSignals(t *testing.T) {
	ch := ForwardSignals()
	if ch == nil {
		t.Fatal("ForwardSignals returned nil channel")
	}
	// StopSignals should close without panic
	StopSignals(ch)

	// Verify channel is closed
	_, ok := <-ch
	if ok {
		t.Error("channel should be closed after StopSignals")
	}
}

// --- Batch handling ---

func TestPipeInspect_BatchBlocksSecurityMessages(t *testing.T) {
	// Before the fix, arrays fail to unmarshal into Message and are forwarded unexamined.
	batch := `[{"jsonrpc":"2.0","id":1,"method":"security/call","params":{}}]` + "\n"
	fwd, errOut := runInspect(t, batch, blockAllConverter)
	if strings.Contains(fwd, "security/call") {
		t.Errorf("batch element should be blocked, but was forwarded: %s", fwd)
	}
	if errOut == "" {
		t.Error("expected error response for blocked batch element")
	}
}

func TestPipeInspect_BatchMixed(t *testing.T) {
	batch := `[{"jsonrpc":"2.0","id":1,"method":"security/call","params":{}},{"jsonrpc":"2.0","id":2,"method":"other/call","params":{}}]` + "\n"
	fwd, errOut := runInspect(t, batch, blockAllConverter)
	if !strings.Contains(fwd, "other/call") {
		t.Errorf("allowed batch element should be forwarded, got: %s", fwd)
	}
	if strings.Contains(fwd, "security/call") {
		t.Errorf("blocked batch element should not be forwarded")
	}
	if errOut == "" {
		t.Error("expected error response for blocked batch element")
	}
}

func TestPipeInspect_BatchInvalidFallthrough(t *testing.T) {
	msg := `[broken json` + "\n"
	fwd, errOut := runInspect(t, msg, blockAllConverter)
	if fwd != msg {
		t.Errorf("invalid batch should pass through, got: %q", fwd)
	}
	if errOut != "" {
		t.Errorf("unexpected error: %s", errOut)
	}
}

func TestPipeInspect_BatchResponseDLP(t *testing.T) {
	// Batch containing a response with DLP-triggering content
	batch := `[{"jsonrpc":"2.0","id":1,"result":{"key":"AKIAIOSFODNN7EXAMPLE"}}]` + "\n"
	fwd, _ := runInspect(t, batch, blockAllConverter)
	if strings.Contains(fwd, "AKIA") {
		t.Errorf("response with AWS key in batch should be blocked by DLP, got: %s", fwd)
	}
}

// --- Notification params DLP ---

func TestPipeInspect_NotificationParamsDLP(t *testing.T) {
	msg := `{"jsonrpc":"2.0","method":"update","params":{"token":"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm"}}` + "\n"
	fwd, _ := runInspect(t, msg, blockAllConverter)
	if strings.Contains(fwd, "ghp_") {
		t.Errorf("notification with GitHub token in params should be blocked by DLP, got: %s", fwd)
	}
}

func TestPipeInspect_NotificationCleanParamsPassthrough(t *testing.T) {
	msg := `{"jsonrpc":"2.0","method":"update","params":{"progress":50}}` + "\n"
	fwd, errOut := runInspect(t, msg, blockAllConverter)
	if fwd != msg {
		t.Errorf("clean notification should pass through, got: %q", fwd)
	}
	if errOut != "" {
		t.Errorf("unexpected error: %s", errOut)
	}
}

// --- Notification security bypass ---
// Before the fix, notifications (method + no id) bypassed the converter
// and rule engine entirely — only DLP scanning ran.

func TestPipeInspect_NotificationBlocksSecurityMethod(t *testing.T) {
	// "security/call" as a notification (no id) must still be blocked.
	msg := `{"jsonrpc":"2.0","method":"security/call","params":{}}` + "\n"
	fwd, _ := runInspect(t, msg, blockAllConverter)
	if strings.Contains(fwd, "security/call") {
		t.Errorf("notification with security method should be blocked, got forwarded: %s", fwd)
	}
}

func TestPipeInspect_NotificationPassesNonSecurityMethod(t *testing.T) {
	// Non-security notifications must still pass through.
	msg := `{"jsonrpc":"2.0","method":"other/call","params":{}}` + "\n"
	fwd, errOut := runInspect(t, msg, blockAllConverter)
	if fwd != msg {
		t.Errorf("non-security notification should pass through, got %q", fwd)
	}
	if errOut != "" {
		t.Errorf("unexpected error: %s", errOut)
	}
}

func TestPipeInspect_NotificationMalformedParamsBlocked(t *testing.T) {
	// "malformed/call" as a notification — converter returns error, must be blocked.
	msg := `{"jsonrpc":"2.0","method":"malformed/call","params":{}}` + "\n"
	fwd, _ := runInspect(t, msg, blockAllConverter)
	if fwd != "" {
		t.Errorf("notification with malformed params should be blocked, got: %s", fwd)
	}
}

func TestPipeInspect_NotificationNoErrorResponseSent(t *testing.T) {
	// Blocked notifications should NOT generate error responses (no id to reply to).
	msg := `{"jsonrpc":"2.0","method":"security/call","params":{}}` + "\n"
	_, errOut := runInspect(t, msg, blockAllConverter)
	if errOut != "" {
		t.Errorf("blocked notification should not generate error response, got: %s", errOut)
	}
}

func TestPipeInspect_BatchNotificationBlocked(t *testing.T) {
	// Batch element as notification must also be blocked.
	batch := `[{"jsonrpc":"2.0","method":"security/call","params":{}}]` + "\n"
	fwd, _ := runInspect(t, batch, blockAllConverter)
	if strings.Contains(fwd, "security/call") {
		t.Errorf("batch notification should be blocked, got: %s", fwd)
	}
}

// --- IsRequest / IsNotification ---

func TestMessage_IsNotification(t *testing.T) {
	tests := []struct {
		name string
		msg  Message
		want bool
	}{
		{"notification", Message{Method: "foo"}, true},
		{"request", Message{Method: "foo", ID: json.RawMessage(`1`)}, false},
		{"response", Message{ID: json.RawMessage(`1`), Result: json.RawMessage(`{}`)}, false},
		{"empty", Message{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.msg.IsNotification(); got != tt.want {
				t.Errorf("IsNotification() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMessage_IsRequest(t *testing.T) {
	tests := []struct {
		name string
		msg  Message
		want bool
	}{
		{"request", Message{Method: "foo", ID: json.RawMessage(`1`)}, true},
		{"notification", Message{Method: "foo"}, false},
		{"response", Message{ID: json.RawMessage(`1`), Result: json.RawMessage(`{}`)}, false},
		{"empty", Message{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.msg.IsRequest(); got != tt.want {
				t.Errorf("IsRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}
