// Package autowrap implements a transparent stdio proxy that auto-detects
// whether the wrapped subprocess speaks ACP or MCP protocol.
//
// It inspects both directions simultaneously:
//   - Inbound (client/IDE -> subprocess): checks for MCP security methods
//   - Outbound (subprocess -> client/IDE): checks for ACP security methods
//
// Method names between ACP and MCP are disjoint, so there is no ambiguity.
package autowrap

import (
	"os"

	"github.com/BakeLens/crust/internal/jsonrpc"
	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/mcpgateway"
	"github.com/BakeLens/crust/internal/rules"
)

var log = logger.New("wrap")

// Run starts the auto-detecting proxy. It spawns the subprocess, wires up stdio,
// and evaluates security-relevant messages from both ACP and MCP protocols.
func Run(engine rules.RuleEvaluator, cmd []string) int {
	return jsonrpc.RunProxy(engine, cmd, os.Stdin, os.Stdout, jsonrpc.ProxyConfig{
		Log:          log,
		ProcessLabel: "Subprocess",
		Inbound:      jsonrpc.PipeConfig{Label: "Inbound", Protocol: "MCP", Convert: mcpgateway.MCPMethodToToolCall},
		Outbound:     jsonrpc.PipeConfig{Label: "Outbound", Protocol: "Stdio", Convert: BothMethodToToolCall, ErrToClient: true},
		ExtraLogLines: []string{
			"Auto-detect mode: inspecting both ACP and MCP methods",
		},
	})
}
