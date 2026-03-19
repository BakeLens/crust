package acpwrap

import (
	"os"

	"github.com/BakeLens/crust/internal/jsonrpc"
	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/rules"
)

var log = logger.New("acp")

// Run starts the ACP proxy. It spawns the agent subprocess, wires up stdio,
// and evaluates security-relevant messages. Returns the agent's exit code.
func Run(engine rules.RuleEvaluator, agentCmd []string) int {
	return jsonrpc.RunProxy(engine, agentCmd, os.Stdin, os.Stdout, jsonrpc.ProxyConfig{
		Log:          log,
		ProcessLabel: "Agent",
		Inbound:      jsonrpc.PipeConfig{Label: "IDE->Agent"},
		Outbound:     jsonrpc.PipeConfig{Label: "Agent->IDE", Protocol: "ACP", Convert: ACPMethodToToolCall},
	})
}
