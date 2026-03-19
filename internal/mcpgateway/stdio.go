package mcpgateway

import (
	"os"

	"github.com/BakeLens/crust/internal/jsonrpc"
	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/rules"
)

var log = logger.New("mcp")

// Run starts the MCP gateway proxy. It spawns the MCP server subprocess, wires up
// stdio, and evaluates security-relevant messages. Returns the server's exit code.
func Run(engine rules.RuleEvaluator, serverCmd []string) int {
	return jsonrpc.RunProxy(engine, serverCmd, os.Stdin, os.Stdout, jsonrpc.ProxyConfig{
		Log:          log,
		ProcessLabel: "MCP server",
		Inbound:      jsonrpc.PipeConfig{Label: "Client->Server", Protocol: "MCP", Convert: MCPMethodToToolCall},
		Outbound:     jsonrpc.PipeConfig{Label: "Server->Client", Protocol: "MCP", Convert: MCPMethodToToolCall},
	})
}
