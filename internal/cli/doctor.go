package cli

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/BakeLens/crust/internal/config"
	"github.com/BakeLens/crust/internal/daemon"
	"github.com/BakeLens/crust/internal/httpproxy"
	"github.com/BakeLens/crust/internal/mcpdiscover"
	"github.com/BakeLens/crust/internal/rules"
)

// DoctorOptions configures the doctor diagnostic run.
type DoctorOptions struct {
	ConfigPath string
	DryRun     bool
}

// DoctorResult holds the aggregate results of a doctor run.
type DoctorResult struct {
	ProviderResults []httpproxy.DoctorResult
	AgentPorts      []AgentPortResult
	LintResult      *rules.LintResult // nil if no user rules
	UserRuleCount   int
	MCPServers      []mcpdiscover.MCPServer
	MCPErrors       []mcpdiscover.DiscoverError
	MCPUnpatched    int
	MCPPatched      int // number patched during this run (0 in dry-run)
	MCPPatchErrors  []mcpdiscover.PatchError
	IssuesFound     int
	IssuesFixed     int
}

// AgentPort describes a well-known AI agent localhost server.
type AgentPort struct {
	Port    int
	Name    string
	HintCmd string
}

// AgentPortResult describes the scan result for a single agent port.
type AgentPortResult struct {
	AgentPort
	Open bool
}

// KnownAgentPorts lists common AI agent servers that expose localhost HTTP/WebSocket.
var KnownAgentPorts = []AgentPort{
	{3000, "OpenClaw", "crust mcp http --listen :3000 --upstream http://localhost:3001"},
	{6274, "MCP Inspector", "crust mcp http --listen :6274 --upstream http://localhost:6275"},
	{6277, "MCP Inspector (SSE)", "crust mcp http --listen :6277 --upstream http://localhost:6278"},
}

// RunDoctor performs all doctor diagnostics and returns structured results.
// The caller (main.go) is responsible for TUI output formatting.
func RunDoctor(opts DoctorOptions) DoctorResult {
	var result DoctorResult

	// Load config
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		cfg = config.DefaultConfig()
	}

	// --- Provider Diagnostics ---
	result.ProviderResults = httpproxy.RunDoctor(httpproxy.DoctorOptions{
		Timeout:       5 * time.Second,
		Retries:       1,
		UserProviders: cfg.Upstream.Providers,
	})

	for _, r := range result.ProviderResults {
		switch r.Status {
		case httpproxy.StatusOK:
			// No issue.
		case httpproxy.StatusAuthError:
			result.IssuesFound++
		case httpproxy.StatusPathError, httpproxy.StatusConnError, httpproxy.StatusOtherError:
			result.IssuesFound++
		}
	}

	// --- Agent Security Scan ---
	result.AgentPorts = ScanAgentPorts(5 * time.Second)
	// Agent port findings are informational (warnings), not counted as issues to fix.

	// --- Rule Linting ---
	rulesDir := cfg.Rules.UserDir
	if rulesDir == "" {
		rulesDir = rules.DefaultUserRulesDir()
	}
	loader := rules.NewLoader(rulesDir)
	userRules, err := loader.LoadUser()
	if err != nil {
		result.IssuesFound++
	}
	result.UserRuleCount = len(userRules)

	if len(userRules) > 0 {
		linter := rules.NewLinter()
		lr := linter.LintRules(userRules)
		result.LintResult = &lr
		result.IssuesFound += lr.Errors + lr.Warns
	}

	// --- MCP Config Scan & Auto-Patch ---
	mcpResult := mcpdiscover.Discover()
	result.MCPServers = mcpResult.Servers
	result.MCPErrors = mcpResult.Errors

	for _, srv := range mcpResult.Servers {
		if !srv.AlreadyWrapped && srv.Transport != mcpdiscover.TransportHTTP {
			result.MCPUnpatched++
		}
	}
	result.IssuesFound += result.MCPUnpatched

	if result.MCPUnpatched > 0 && !opts.DryRun {
		crustBin := daemon.ResolveCrustBin()
		if crustBin != "" {
			patchResult := mcpdiscover.PatchConfigs(crustBin)
			result.MCPPatched = patchResult.Patched
			result.MCPPatchErrors = patchResult.Errors
			result.IssuesFixed += patchResult.Patched
		}
	}

	return result
}

// ScanAgentPorts checks if known agent servers are listening on localhost.
func ScanAgentPorts(timeout time.Duration) []AgentPortResult {
	dialer := &net.Dialer{Timeout: timeout}
	results := make([]AgentPortResult, 0, len(KnownAgentPorts))
	for _, ap := range KnownAgentPorts {
		addr := fmt.Sprintf("127.0.0.1:%d", ap.Port)
		conn, err := dialer.DialContext(context.Background(), "tcp", addr)
		open := conn != nil && err == nil
		if conn != nil {
			conn.Close()
		}
		results = append(results, AgentPortResult{AgentPort: ap, Open: open})
	}
	return results
}
