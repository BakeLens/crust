package mcpgateway

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BakeLens/crust/internal/jsonrpc"
	"github.com/BakeLens/crust/internal/pathutil"
	"github.com/BakeLens/crust/internal/testutil"
)

// skipE2E skips if -short or npx not available.
func skipE2E(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("E2E: skipped in -short mode")
	}
	if _, err := exec.LookPath("npx"); err != nil {
		t.Skip("E2E: npx not found in PATH")
	}
}

// toJSONPath converts a filesystem path to forward slashes for safe embedding
// in JSON strings. On Windows, backslashes in paths would be misinterpreted as
// JSON escape sequences, producing invalid JSON that the MCP server cannot parse.
func toJSONPath(p string) string {
	return pathutil.ToSlash(p)
}

// runMCPE2E runs the MCP proxy against the real filesystem server and returns
// all JSON-RPC responses received by the client.
func runMCPE2E(t *testing.T, dir string, messages []string) []testResponse {
	t.Helper()
	// Use dir as $HOME so that $HOME-based security rules (SSH keys, etc.)
	// match files inside the test directory.
	engine := testutil.NewEngineWithHome(t, dir)
	input := strings.Join(messages, "\n") + "\n"
	stdinR := io.NopCloser(strings.NewReader(input))
	var stdout strings.Builder

	done := make(chan int, 1)
	go func() {
		done <- jsonrpc.RunProxy(engine,
			[]string{"npx", "-y", "@modelcontextprotocol/server-filesystem", dir},
			stdinR, &stdout, jsonrpc.ProxyConfig{
				Log:          testLog,
				ProcessLabel: "MCP server",
				Inbound:      jsonrpc.PipeConfig{Label: "Client->Server", Protocol: "MCP", Convert: MCPMethodToToolCall},
				Outbound:     jsonrpc.PipeConfig{Label: "Server->Client", Protocol: "MCP", Convert: MCPMethodToToolCall, ErrToClient: true},
			})
	}()

	select {
	case <-done:
		return parseResponses(t, stdout.String())
	case <-time.After(30 * time.Second):
		t.Fatal("E2E test timed out (30s)")
		return nil
	}
}

// --- E2E Tests ---

func TestE2E_Initialize(t *testing.T) {
	skipE2E(t)
	dir := setupTestDir(t)

	responses := runMCPE2E(t, dir, initMessages()[:1]) // just initialize, no notification

	resp := findByID(responses, 1)
	if resp == nil {
		t.Fatal("no response for initialize (id=1)")
		return
	}
	if resp.Error != nil {
		t.Fatalf("initialize returned error: %s", resp.Error.Message)
	}

	// Verify response has protocolVersion
	var result map[string]any
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("failed to parse init result: %v", err)
	}
	if _, ok := result["protocolVersion"]; !ok {
		t.Error("initialize response missing protocolVersion")
	}
	if _, ok := result["capabilities"]; !ok {
		t.Error("initialize response missing capabilities")
	}
	if _, ok := result["serverInfo"]; !ok {
		t.Error("initialize response missing serverInfo")
	}
}

func TestE2E_ToolsList(t *testing.T) {
	skipE2E(t)
	dir := setupTestDir(t)

	messages := append(initMessages(),
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
	)
	responses := runMCPE2E(t, dir, messages)

	resp := findByID(responses, 2)
	if resp == nil {
		t.Fatal("no response for tools/list (id=2)")
		return
	}
	if resp.Error != nil {
		t.Fatalf("tools/list returned error: %s", resp.Error.Message)
	}

	var result map[string]any
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("failed to parse tools/list result: %v", err)
	}
	tools, ok := result["tools"].([]any)
	if !ok || len(tools) == 0 {
		t.Fatal("tools/list returned no tools")
	}

	// Verify known tools exist
	toolNames := make(map[string]bool)
	for _, tool := range tools {
		if m, ok := tool.(map[string]any); ok {
			if name, ok := m["name"].(string); ok {
				toolNames[name] = true
			}
		}
	}
	for _, want := range []string{"read_text_file", "write_file"} {
		if !toolNames[want] {
			t.Errorf("tools/list missing tool %q, got: %v", want, toolNames)
		}
	}
}

func TestE2E_ReadAllowed(t *testing.T) {
	skipE2E(t)
	dir := setupTestDir(t)

	messages := append(initMessages(),
		fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"%s/safe.txt"}}}`, toJSONPath(dir)),
	)
	responses := runMCPE2E(t, dir, messages)

	resp := findByID(responses, 3)
	if resp == nil {
		t.Fatal("no response for read_text_file safe.txt (id=3)")
		return
	}
	if resp.Error != nil {
		t.Fatalf("read_text_file returned error: code=%d msg=%s", resp.Error.Code, resp.Error.Message)
	}

	// Verify the response contains the actual file content
	if !strings.Contains(string(resp.Result), "hello world") {
		t.Errorf("expected file content 'hello world' in response, got: %s", string(resp.Result))
	}
}

func TestE2E_ReadBlocked_Env(t *testing.T) {
	skipE2E(t)
	dir := setupTestDir(t)

	messages := append(initMessages(),
		fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"%s/.env"}}}`, toJSONPath(dir)),
	)
	responses := runMCPE2E(t, dir, messages)

	resp := findByID(responses, 3)
	if resp == nil {
		t.Fatal("no response for blocked .env read (id=3)")
		return
	}
	if resp.Error == nil {
		t.Fatalf("expected Crust block error for .env read, got success: %s", string(resp.Result))
	}
	if resp.Error.Code != jsonrpc.BlockedError {
		t.Errorf("error code = %d, want %d", resp.Error.Code, jsonrpc.BlockedError)
	}
	if !strings.Contains(resp.Error.Message, "[Crust]") {
		t.Errorf("error message missing [Crust] prefix: %s", resp.Error.Message)
	}
}

func TestE2E_ReadBlocked_SSHKey(t *testing.T) {
	skipE2E(t)
	dir := setupTestDir(t)

	messages := append(initMessages(),
		fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"%s/.ssh/id_rsa"}}}`, toJSONPath(dir)),
	)
	responses := runMCPE2E(t, dir, messages)

	resp := findByID(responses, 3)
	if resp == nil {
		t.Fatal("no response for blocked SSH key read (id=3)")
		return
	}
	if resp.Error == nil {
		t.Fatalf("expected Crust block error for SSH key read, got success: %s", string(resp.Result))
	}
	if resp.Error.Code != jsonrpc.BlockedError {
		t.Errorf("error code = %d, want %d", resp.Error.Code, jsonrpc.BlockedError)
	}
}

func TestE2E_WriteAllowed(t *testing.T) {
	skipE2E(t)
	dir := setupTestDir(t)
	outFile := filepath.Join(dir, "output.txt")

	messages := append(initMessages(),
		fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"%s","content":"written by e2e test"}}}`, toJSONPath(outFile)),
	)
	responses := runMCPE2E(t, dir, messages)

	resp := findByID(responses, 3)
	if resp == nil {
		t.Fatal("no response for write_file (id=3)")
		return
	}
	if resp.Error != nil {
		t.Fatalf("write_file returned error: code=%d msg=%s", resp.Error.Code, resp.Error.Message)
	}

	// Verify the file was actually written
	content, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed to read written file: %v", err)
	}
	if string(content) != "written by e2e test" {
		t.Errorf("file content = %q, want %q", string(content), "written by e2e test")
	}
}

func TestE2E_WriteBlocked_Env(t *testing.T) {
	skipE2E(t)
	dir := setupTestDir(t)
	envContent, _ := os.ReadFile(filepath.Join(dir, ".env"))

	messages := append(initMessages(),
		fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"%s/.env","content":"STOLEN=true"}}}`, toJSONPath(dir)),
	)
	responses := runMCPE2E(t, dir, messages)

	resp := findByID(responses, 3)
	if resp == nil {
		t.Fatal("no response for blocked .env write (id=3)")
		return
	}
	if resp.Error == nil {
		t.Fatalf("expected Crust block error for .env write, got success: %s", string(resp.Result))
	}
	if resp.Error.Code != jsonrpc.BlockedError {
		t.Errorf("error code = %d, want %d", resp.Error.Code, jsonrpc.BlockedError)
	}

	// Verify the .env file was NOT modified
	after, _ := os.ReadFile(filepath.Join(dir, ".env"))
	if string(after) != string(envContent) {
		t.Errorf(".env was modified despite being blocked: %q → %q", envContent, after)
	}
}

func TestE2E_MixedStream(t *testing.T) {
	skipE2E(t)
	dir := setupTestDir(t)

	messages := append(initMessages(),
		// id=2: tools/list (allowed — not tools/call)
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
		// id=3: read .env (BLOCKED by inbound path rules)
		fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"%s/.env"}}}`, toJSONPath(dir)),
		// id=4: read safe.txt (allowed)
		fmt.Sprintf(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"%s/safe.txt"}}}`, toJSONPath(dir)),
		// id=5: write .env (BLOCKED by inbound path rules)
		fmt.Sprintf(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"%s/.env","content":"STOLEN"}}}`, toJSONPath(dir)),
	)
	responses := runMCPE2E(t, dir, messages)

	// id=1: initialize — should succeed
	if r := findByID(responses, 1); r == nil || r.Error != nil {
		t.Error("initialize (id=1) should succeed")
	}

	// id=2: tools/list — should succeed
	if r := findByID(responses, 2); r == nil || r.Error != nil {
		t.Error("tools/list (id=2) should succeed")
	}

	// id=3: read .env — should be blocked
	if r := findByID(responses, 3); r == nil {
		t.Error("expected response for blocked .env read (id=3)")
	} else if r.Error == nil {
		t.Error("read .env (id=3) should be blocked")
	} else if r.Error.Code != jsonrpc.BlockedError {
		t.Errorf("read .env error code = %d, want %d", r.Error.Code, jsonrpc.BlockedError)
	}

	// id=4: read safe.txt — should succeed with content
	if r := findByID(responses, 4); r == nil {
		t.Error("expected response for safe.txt read (id=4)")
	} else if r.Error != nil {
		t.Errorf("read safe.txt (id=4) should succeed, got error: %s", r.Error.Message)
	} else if !strings.Contains(string(r.Result), "hello world") {
		t.Errorf("read safe.txt (id=4) missing content, got: %s", string(r.Result))
	}

	// id=5: write .env — should be blocked
	if r := findByID(responses, 5); r == nil {
		t.Error("expected response for blocked .env write (id=5)")
	} else if r.Error == nil {
		t.Error("write .env (id=5) should be blocked")
	} else if r.Error.Code != jsonrpc.BlockedError {
		t.Errorf("write .env error code = %d, want %d", r.Error.Code, jsonrpc.BlockedError)
	}
}

// --- Response DLP E2E Tests ---
// These test the outbound direction: the REAL MCP server reads files with
// innocent names but secret content. Crust's response DLP blocks the response
// before it reaches the client.

func TestE2E_ResponseDLP_AWSKey(t *testing.T) {
	skipE2E(t)
	dir := setupTestDir(t)

	// config.txt contains an AWS access key but is NOT a .env file
	messages := append(initMessages(),
		fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"%s/config.txt"}}}`, toJSONPath(dir)),
	)
	responses := runMCPE2E(t, dir, messages)

	resp := findByID(responses, 3)
	if resp == nil {
		t.Fatal("no response for config.txt read (id=3)")
		return
	}
	// Response DLP should block: the server returned the file content which contains an AWS key
	if resp.Error == nil {
		t.Fatalf("expected DLP block for AWS key in config.txt, got success: %s", string(resp.Result))
	}
	if resp.Error.Code != jsonrpc.BlockedError {
		t.Errorf("error code = %d, want %d", resp.Error.Code, jsonrpc.BlockedError)
	}
	if !strings.Contains(resp.Error.Message, "[Crust]") {
		t.Errorf("error message missing [Crust]: %s", resp.Error.Message)
	}
	if !strings.Contains(resp.Error.Message, "AWS") {
		t.Errorf("error message should mention AWS: %s", resp.Error.Message)
	}
}

func TestE2E_ResponseDLP_GitHubToken(t *testing.T) {
	skipE2E(t)
	dir := setupTestDir(t)

	// tokens.txt contains a GitHub personal access token
	messages := append(initMessages(),
		fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"%s/tokens.txt"}}}`, toJSONPath(dir)),
	)
	responses := runMCPE2E(t, dir, messages)

	resp := findByID(responses, 3)
	if resp == nil {
		t.Fatal("no response for tokens.txt read (id=3)")
		return
	}
	if resp.Error == nil {
		t.Fatalf("expected DLP block for GitHub token in tokens.txt, got success: %s", string(resp.Result))
	}
	if resp.Error.Code != jsonrpc.BlockedError {
		t.Errorf("error code = %d, want %d", resp.Error.Code, jsonrpc.BlockedError)
	}
	if !strings.Contains(resp.Error.Message, "GitHub") {
		t.Errorf("error message should mention GitHub: %s", resp.Error.Message)
	}
}

func TestE2E_ResponseDLP_CleanFile(t *testing.T) {
	skipE2E(t)
	dir := setupTestDir(t)

	// notes.txt has no secrets — should pass through
	messages := append(initMessages(),
		fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"%s/notes.txt"}}}`, toJSONPath(dir)),
	)
	responses := runMCPE2E(t, dir, messages)

	resp := findByID(responses, 3)
	if resp == nil {
		t.Fatal("no response for notes.txt read (id=3)")
		return
	}
	if resp.Error != nil {
		t.Fatalf("notes.txt should pass DLP (no secrets), got error: code=%d msg=%s", resp.Error.Code, resp.Error.Message)
	}
	if !strings.Contains(string(resp.Result), "no secrets here") {
		t.Errorf("expected file content in response, got: %s", string(resp.Result))
	}
}

func TestE2E_ResponseDLP_MixedStream(t *testing.T) {
	skipE2E(t)
	dir := setupTestDir(t)

	messages := append(initMessages(),
		// id=2: read clean file (ALLOWED — passes both inbound and response DLP)
		fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"%s/notes.txt"}}}`, toJSONPath(dir)),
		// id=3: read file with AWS key (BLOCKED by response DLP)
		fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"%s/config.txt"}}}`, toJSONPath(dir)),
		// id=4: read .env (BLOCKED by inbound path rules — never reaches server)
		fmt.Sprintf(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"%s/.env"}}}`, toJSONPath(dir)),
		// id=5: read file with GitHub token (BLOCKED by response DLP)
		fmt.Sprintf(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"%s/tokens.txt"}}}`, toJSONPath(dir)),
		// id=6: read safe file (ALLOWED)
		fmt.Sprintf(`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"%s/safe.txt"}}}`, toJSONPath(dir)),
	)
	responses := runMCPE2E(t, dir, messages)

	// id=2: clean file — should pass
	if r := findByID(responses, 2); r == nil {
		t.Error("expected response for notes.txt (id=2)")
	} else if r.Error != nil {
		t.Errorf("notes.txt (id=2) should pass, got error: %s", r.Error.Message)
	}

	// id=3: AWS key in response — blocked by response DLP
	if r := findByID(responses, 3); r == nil {
		t.Error("expected response for config.txt (id=3)")
	} else if r.Error == nil {
		t.Error("config.txt (id=3) should be blocked by response DLP")
	} else if r.Error.Code != jsonrpc.BlockedError {
		t.Errorf("config.txt error code = %d, want %d", r.Error.Code, jsonrpc.BlockedError)
	}

	// id=4: .env — blocked by inbound path rules
	if r := findByID(responses, 4); r == nil {
		t.Error("expected response for .env (id=4)")
	} else if r.Error == nil {
		t.Error(".env (id=4) should be blocked by inbound rules")
	}

	// id=5: GitHub token in response — blocked by response DLP
	if r := findByID(responses, 5); r == nil {
		t.Error("expected response for tokens.txt (id=5)")
	} else if r.Error == nil {
		t.Error("tokens.txt (id=5) should be blocked by response DLP")
	} else if r.Error.Code != jsonrpc.BlockedError {
		t.Errorf("tokens.txt error code = %d, want %d", r.Error.Code, jsonrpc.BlockedError)
	}

	// id=6: safe file — should pass
	if r := findByID(responses, 6); r == nil {
		t.Error("expected response for safe.txt (id=6)")
	} else if r.Error != nil {
		t.Errorf("safe.txt (id=6) should pass, got error: %s", r.Error.Message)
	} else if !strings.Contains(string(r.Result), "hello world") {
		t.Errorf("safe.txt (id=6) missing content, got: %s", string(r.Result))
	}
}
