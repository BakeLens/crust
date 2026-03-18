//go:build libcrust

package libcrust

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BakeLens/crust/internal/daemon"
	"github.com/BakeLens/crust/internal/daemon/registry"
	"github.com/BakeLens/crust/internal/eventlog"
)

// protectState tracks the auto-protect lifecycle.
var protect struct {
	mu       sync.Mutex
	running  bool
	port     int
	evalLn   net.Listener
	evalPort int
}

// StartProtect starts the full protection stack:
// 1. Starts HTTP proxy in auto mode on an auto-assigned port
// 2. Patches all registered agent configs (HTTP URL + MCP wrapping)
// Returns the proxy port, or error.
func StartProtect() (int, error) {
	protect.mu.Lock()
	defer protect.mu.Unlock()

	if protect.running {
		return protect.port, nil
	}

	// Start proxy in auto mode (port 0 = auto-assign, empty upstream = auto mode).
	if err := StartProxy(0, "", "", ""); err != nil {
		return 0, fmt.Errorf("start proxy: %w", err)
	}

	// Get the assigned port.
	addr := ProxyAddress()
	if addr == "" {
		StopProxy()
		return 0, fmt.Errorf("proxy started but address is empty")
	}
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		StopProxy()
		return 0, fmt.Errorf("parse proxy address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		StopProxy()
		return 0, fmt.Errorf("parse port %q: %w", portStr, err)
	}

	// Patch all agent configs to route through the proxy.
	daemon.PatchAgentConfigs(port)

	// Install Claude Code PreToolUse hook for direct tool call interception.
	crustBin := daemon.ResolveCrustBin()
	if crustBin != "" {
		// Clean up stale hooks.json from the bug where hooks were written
		// to the wrong file (should be in settings.json, not hooks.json).
		cleanupStaleHooksFile()

		if err := InstallClaudeHook(crustBin); err != nil {
			// Non-fatal: Claude Code hooks are supplementary protection.
			fmt.Fprintf(os.Stderr, "crust: install claude hook: %v\n", err)
		} else {
			// Mark Claude Code as protected — the hook provides tool call
			// interception even when MCP config patching found nothing.
			registry.Default.MarkPatched("Claude Code")
		}
	}

	// Start internal evaluate API on a separate port (not exposed to agents).
	evalPort, err := startEvalServer()
	if err != nil {
		// Non-fatal: hooks will fall back to cold-start evaluation.
		fmt.Fprintf(os.Stderr, "crust: start eval server: %v\n", err)
	}

	protect.running = true
	protect.port = port
	protect.evalPort = evalPort

	// Write eval port so hook processes can find the running instance.
	// Skip when evalPort is 0 (server failed to start) to avoid writing
	// a zero port that would cause hook processes to connect to nothing.
	if evalPort > 0 {
		writePortFile(evalPort)
	}

	return port, nil
}

// StopProtect tears down the full protection stack:
// 1. Restores all patched agent configs
// 2. Stops the HTTP proxy
func StopProtect() {
	protect.mu.Lock()
	defer protect.mu.Unlock()

	if !protect.running {
		return
	}

	// Remove Claude Code hooks.
	if err := UninstallClaudeHook(); err != nil {
		fmt.Fprintf(os.Stderr, "crust: uninstall claude hook: %v\n", err)
	}

	daemon.RestoreAgentConfigs()
	StopProxy()
	stopEvalServer()
	removePortFile()
	protect.running = false
	protect.port = 0
	protect.evalPort = 0
}

// ProtectPort returns the proxy port, or 0 if not running.
func ProtectPort() int {
	protect.mu.Lock()
	defer protect.mu.Unlock()
	return protect.port
}

// ProtectStatus returns the current protection status as JSON.
func ProtectStatus() string {
	protect.mu.Lock()
	port := protect.port
	running := protect.running
	protect.mu.Unlock()

	// Get list of patched agents from registry.
	var patched []string
	for _, t := range registry.Default.Targets() {
		if registry.Default.IsPatched(t.Name()) {
			patched = append(patched, t.Name())
		}
	}
	if patched == nil {
		patched = []string{}
	}

	status := map[string]any{
		"active":         running,
		"proxy_port":     port,
		"patched_agents": patched,
	}
	out, _ := json.Marshal(status)
	return string(out)
}

// ListAgents returns a JSON array of all registered agents with their status.
func ListAgents() string {
	type agentInfo struct {
		Name    string `json:"name"`
		Patched bool   `json:"patched"`
	}
	var agents []agentInfo
	for _, t := range registry.Default.Targets() {
		agents = append(agents, agentInfo{
			Name:    t.Name(),
			Patched: registry.Default.IsPatched(t.Name()),
		})
	}
	if agents == nil {
		agents = []agentInfo{}
	}
	out, _ := json.Marshal(agents)
	return string(out)
}

// EnableAgent patches a single agent by name.
func EnableAgent(name string) error {
	protect.mu.Lock()
	port := protect.port
	protect.mu.Unlock()

	crustBin := daemon.ResolveCrustBin()
	for _, t := range registry.Default.Targets() {
		if t.Name() == name {
			return t.Patch(port, crustBin)
		}
	}
	return fmt.Errorf("agent %q not found", name)
}

// DisableAgent restores a single agent by name.
func DisableAgent(name string) error {
	for _, t := range registry.Default.Targets() {
		if t.Name() == name {
			return t.Restore()
		}
	}
	return fmt.Errorf("agent %q not found", name)
}

// startEvalServer starts a localhost-only TCP server for hook evaluation.
// Protocol: connect → write JSON line → read JSON line → close.
// Separate from the proxy to prevent agents from probing rules.
func startEvalServer() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("listen eval server: %w", err)
	}
	protect.evalLn = ln

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go handleEvalConn(conn)
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return port, nil
}

// handleEvalConn handles a single evaluation request on a raw TCP connection.
// Protocol: read one JSON line, evaluate, write one JSON line, close.
func handleEvalConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1<<20), 1<<20) // 1 MB max
	if !scanner.Scan() {
		return
	}
	line := scanner.Bytes()

	var req struct {
		ToolName  string          `json:"tool_name"`
		ToolInput json.RawMessage `json:"tool_input"`
	}
	if json.Unmarshal(line, &req) != nil || req.ToolName == "" {
		_, _ = conn.Write([]byte(`{"matched":false}` + "\n"))
		return
	}

	argsJSON := "{}"
	if len(req.ToolInput) > 0 {
		argsJSON = string(req.ToolInput)
	}

	result := Evaluate(req.ToolName, argsJSON)
	_, _ = conn.Write(append([]byte(result), '\n'))

	// Record event for the GUI event stream and metrics.
	var evalResult struct {
		Matched  bool   `json:"matched"`
		RuleName string `json:"rule_name"`
		Action   string `json:"action"`
	}
	if json.Unmarshal([]byte(result), &evalResult) != nil {
		return
	}
	eventlog.Record(eventlog.Event{
		Layer:      eventlog.LayerHook,
		ToolName:   req.ToolName,
		Arguments:  req.ToolInput,
		Protocol:   "Hook",
		Direction:  "inbound",
		WasBlocked: evalResult.Matched && evalResult.Action == "block",
		RuleName:   evalResult.RuleName,
	})
}

// stopEvalServer shuts down the internal evaluate server.
func stopEvalServer() {
	if protect.evalLn != nil {
		protect.evalLn.Close()
		protect.evalLn = nil
	}
}

// portFilePath returns ~/.crust/protect.port
func portFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".crust", "protect.port")
}

// writePortFile writes the proxy port to ~/.crust/protect.port.
// Hook processes read this to find the running evaluation endpoint.
func writePortFile(port int) {
	p := portFilePath()
	if p == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	_ = os.WriteFile(p, []byte(strconv.Itoa(port)), 0o600)
}

// removePortFile removes ~/.crust/protect.port.
func removePortFile() {
	p := portFilePath()
	if p != "" {
		_ = os.Remove(p)
	}
}

// ReadPortFile reads the proxy port from ~/.crust/protect.port.
// Returns 0 if the file doesn't exist or is invalid.
func ReadPortFile() int {
	p := portFilePath()
	if p == "" {
		return 0
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(string(data))
	if err != nil {
		return 0
	}
	return port
}

// EvaluateViaRunningInstance evaluates a tool call by connecting to a running
// crust instance's TCP eval server. This avoids cold-starting the rule engine
// (~4s) by reusing the already-loaded engine in the running GUI/CLI process.
//
// hookInput is the raw JSON from Claude Code's PreToolUse hook (contains
// tool_name and tool_input fields among others).
//
// Returns the evaluation result JSON, or empty string if no running instance
// is available (caller should fall back to cold-start Evaluate).
func EvaluateViaRunningInstance(hookInput string) string {
	port := ReadPortFile()
	if port == 0 {
		return ""
	}

	// Raw TCP: connect → write JSON line → read JSON line → close.
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		return "" // instance not reachable, fall back
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Send hook input as a single line (strip any newlines).
	line := strings.ReplaceAll(strings.ReplaceAll(hookInput, "\n", " "), "\r", "")
	if _, err := fmt.Fprintf(conn, "%s\n", line); err != nil {
		return ""
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	if !scanner.Scan() {
		return ""
	}
	return scanner.Text()
}
