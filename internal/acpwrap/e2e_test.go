package acpwrap

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/BakeLens/crust/internal/jsonrpc"
	"github.com/BakeLens/crust/internal/testutil"
)

// mockAgentBin is the path to the compiled mock-acp-agent binary.
// Set by TestMain; empty if build failed (E2E tests skip gracefully).
var mockAgentBin string

func TestMain(m *testing.M) {
	os.Exit(buildAndRun(m))
}

func buildAndRun(m *testing.M) int {
	tmp, err := os.MkdirTemp("", "crust-acp-e2e-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot create temp dir for mock agent: %v\n", err)
		return m.Run()
	}
	defer os.RemoveAll(tmp)

	bin := filepath.Join(tmp, "mock-acp-agent")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, "../../cmd/mock-acp-agent")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot build mock-acp-agent: %v\n", err)
		return m.Run()
	}
	mockAgentBin = bin
	return m.Run()
}

func skipACPE2E(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("E2E: skipped in -short mode")
	}
	if mockAgentBin == "" {
		t.Skip("E2E: mock-acp-agent not built")
	}
}

// acpMessage is a parsed JSON-RPC message from proxy output.
type acpMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// runACPE2E starts the ACP proxy with the mock agent and returns all JSONL
// messages received by the IDE side (responses + forwarded agent requests).
func runACPE2E(t *testing.T, messages []string) []acpMessage {
	t.Helper()
	// Use /home/user as HOME so $HOME-based rules (SSH keys) match mock agent paths.
	engine := testutil.NewEngineWithHome(t, "/home/user")
	input := strings.Join(messages, "\n") + "\n"
	stdinR := io.NopCloser(strings.NewReader(input))
	var stdout strings.Builder

	done := make(chan int, 1)
	go func() {
		done <- jsonrpc.RunProxy(engine, []string{mockAgentBin},
			stdinR, &stdout, jsonrpc.ProxyConfig{
				Log:          testLog,
				ProcessLabel: "Agent",
				Inbound:      jsonrpc.PipeConfig{Label: "IDE->Agent"},
				Outbound:     jsonrpc.PipeConfig{Label: "Agent->IDE", Protocol: "ACP", Convert: ACPMethodToToolCall},
			})
	}()

	select {
	case <-done:
		return parseACPMessages(t, stdout.String())
	case <-time.After(30 * time.Second):
		t.Fatal("E2E test timed out (30s)")
		return nil
	}
}

func parseACPMessages(t *testing.T, output string) []acpMessage {
	t.Helper()
	var msgs []acpMessage
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var msg acpMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			t.Logf("skipping non-JSON line: %s", line)
			continue
		}
		msgs = append(msgs, msg)
	}
	return msgs
}

func findACPByID(msgs []acpMessage, id int) *acpMessage {
	target := fmt.Sprintf("%d", id)
	for i := range msgs {
		if string(msgs[i].ID) == target {
			return &msgs[i]
		}
	}
	return nil
}

func acpInitMessages() []string {
	return []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1,"clientInfo":{"name":"crust-e2e","version":"1.0.0"}}}`,
		`{"jsonrpc":"2.0","method":"initialized","params":{}}`,
	}
}

// --- E2E Tests ---

func TestE2E_ACP_Initialize(t *testing.T) {
	skipACPE2E(t)

	responses := runACPE2E(t, acpInitMessages()[:1])

	resp := findACPByID(responses, 1)
	if resp == nil {
		t.Fatal("no response for initialize (id=1)")
		return
	}
	if resp.Error != nil {
		t.Fatalf("initialize returned error: %s", resp.Error.Message)
	}

	var result map[string]any
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("failed to parse init result: %v", err)
	}
	if _, ok := result["agentInfo"]; !ok {
		t.Error("initialize response missing agentInfo")
	}
}

func TestE2E_ACP_SessionCreate_BlocksMaliciousReads(t *testing.T) {
	skipACPE2E(t)

	messages := append(acpInitMessages(),
		`{"jsonrpc":"2.0","id":2,"method":"session/create","params":{"sessionInfo":{"name":"test"}}}`,
	)
	responses := runACPE2E(t, messages)

	// Agent's session/create response should arrive at IDE
	resp := findACPByID(responses, 2)
	if resp == nil {
		t.Fatal("no response for session/create (id=2)")
		return
	}
	if resp.Error != nil {
		t.Fatalf("session/create returned error: %s", resp.Error.Message)
	}

	// Mock agent auto-triggers three reads after session/create:
	//   id=100: /app/.env          → BLOCKED by **/.env rule
	//   id=101: /home/user/.ssh/id_rsa → BLOCKED by $HOME/.ssh/id_* rule
	//   id=102: /app/src/main.go   → ALLOWED (not sensitive)
	if r := findACPByID(responses, 100); r != nil {
		t.Errorf(".env read (id=100) should be blocked, but was forwarded: method=%s", r.Method)
	}
	if r := findACPByID(responses, 101); r != nil {
		t.Errorf("SSH key read (id=101) should be blocked, but was forwarded: method=%s", r.Method)
	}
	if r := findACPByID(responses, 102); r == nil {
		t.Error("legitimate read /app/src/main.go (id=102) should be forwarded to IDE")
	}
}

func TestE2E_ACP_Prompt_BlocksAttackSequence(t *testing.T) {
	skipACPE2E(t)

	messages := append(acpInitMessages(),
		`{"jsonrpc":"2.0","id":2,"method":"session/create","params":{"sessionInfo":{"name":"test"}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"session/prompt","params":{"sessionId":"test-session-1","text":"run malicious test"}}`,
	)
	responses := runACPE2E(t, messages)

	// session/prompt response should arrive at IDE
	resp := findACPByID(responses, 3)
	if resp == nil {
		t.Fatal("no response for session/prompt (id=3)")
		return
	}
	if resp.Error != nil {
		t.Fatalf("session/prompt returned error: %s", resp.Error.Message)
	}

	// After session/create: ids 100-102 (3 reads, 2 blocked)
	// After "malicious" prompt: ids 103-107
	//   103: /app/.env read            → BLOCKED by **/.env
	//   104: /home/user/.ssh/id_rsa    → BLOCKED by $HOME/.ssh/id_*
	//   105: /app/.env.stolen write    → BLOCKED by **/.env.*
	//   106: terminal/create cat /etc/shadow → BLOCKED by /etc/shadow
	//   107: /app/src/main.go read     → ALLOWED
	for _, blocked := range []int{103, 104, 105, 106} {
		if r := findACPByID(responses, blocked); r != nil {
			t.Errorf("attack request (id=%d) should be blocked, but was forwarded: method=%s", blocked, r.Method)
		}
	}

	if r := findACPByID(responses, 107); r == nil {
		t.Error("legitimate read /app/src/main.go (id=107) should be forwarded to IDE")
	}
}

func TestE2E_ACP_NormalPrompt_Passthrough(t *testing.T) {
	skipACPE2E(t)

	messages := append(acpInitMessages(),
		`{"jsonrpc":"2.0","id":2,"method":"session/create","params":{"sessionInfo":{"name":"test"}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"session/prompt","params":{"sessionId":"test-session-1","text":"hello world"}}`,
	)
	responses := runACPE2E(t, messages)

	resp := findACPByID(responses, 3)
	if resp == nil {
		t.Fatal("no response for session/prompt (id=3)")
		return
	}
	if resp.Error != nil {
		t.Fatalf("session/prompt returned error: %s", resp.Error.Message)
	}

	// With non-attack prompt, agent reads /app/README.md (allowed).
	// session/create: 100 (blocked), 101 (blocked), 102 (allowed)
	// normal prompt: 103 (/app/README.md — allowed)
	if r := findACPByID(responses, 103); r == nil {
		t.Error("normal README.md read (id=103) should be forwarded to IDE")
	}
}
