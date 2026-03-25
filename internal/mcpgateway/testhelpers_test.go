package mcpgateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BakeLens/crust/internal/jsonrpc"
	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/testutil"
)

// --- Shared test infrastructure ---

var testLog = logger.New("mcp-test")

// runPipe runs PipeInspect with MCPMethodToToolCall and returns what was
// forwarded and what error responses were generated.
func runPipe(t *testing.T, input string) (fwd, errOut string) {
	t.Helper()
	engine := testutil.NewEngine(t)
	var fwdBuf, errBuf bytes.Buffer
	fwdWriter := jsonrpc.NewLockedWriter(&fwdBuf)
	errWriter := jsonrpc.NewLockedWriter(&errBuf)
	jsonrpc.PipeInspect(testLog, engine, strings.NewReader(input),
		fwdWriter, errWriter, MCPMethodToToolCall, "MCP", "Client->Server", nil)
	return fwdBuf.String(), errBuf.String()
}

// setupTestDir creates a temp directory with test files for the filesystem server.
// It resolves symlinks so paths match on macOS (/var → /private/var).
func setupTestDir(t *testing.T) string {
	t.Helper()
	raw := t.TempDir()
	dir, err := filepath.EvalSymlinks(raw)
	if err != nil {
		t.Fatalf("failed to resolve symlinks for %s: %v", raw, err)
	}

	// Safe files
	os.WriteFile(filepath.Join(dir, "safe.txt"), []byte("hello world"), 0o644)
	os.MkdirAll(filepath.Join(dir, "subdir"), 0o755)
	os.WriteFile(filepath.Join(dir, "subdir", "code.go"), []byte("package main"), 0o644)

	// Sensitive files (should be blocked by Crust path rules)
	os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET_KEY=sk-1234"), 0o644)
	os.MkdirAll(filepath.Join(dir, ".ssh"), 0o700)
	os.WriteFile(filepath.Join(dir, ".ssh", "id_rsa"), []byte("fake-private-key"), 0o600)

	// Files with embedded secrets (should be blocked by response DLP)
	// These files have innocent names but contain real API key patterns.
	os.WriteFile(filepath.Join(dir, "config.txt"),
		[]byte("# App config\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nREGION=us-east-1"), 0o644)
	os.WriteFile(filepath.Join(dir, "tokens.txt"),
		[]byte("github_token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "notes.txt"),
		[]byte("TODO: refactor auth module\nno secrets here"), 0o644)

	return dir
}

// testResponse represents a parsed JSON-RPC response from proxy output.
type testResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// parseResponses parses JSONL output into testResponse structs.
func parseResponses(t *testing.T, output string) []testResponse {
	t.Helper()
	var responses []testResponse
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var resp testResponse
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			t.Logf("skipping non-JSON line: %s", line)
			continue
		}
		responses = append(responses, resp)
	}
	return responses
}

// findByID finds a response with the given integer ID.
func findByID(responses []testResponse, id int) *testResponse {
	target := fmt.Sprintf("%d", id)
	for i := range responses {
		if string(responses[i].ID) == target {
			return &responses[i]
		}
	}
	return nil
}

// initMessages returns the standard MCP handshake messages (initialize + initialized notification).
func initMessages() []string {
	return []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"crust-e2e","version":"1.0.0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`,
	}
}
