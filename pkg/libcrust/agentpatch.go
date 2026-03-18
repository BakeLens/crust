//go:build libcrust

package libcrust

import "github.com/BakeLens/crust/internal/daemon"

// PatchAgents patches all registered agent configs to route through the proxy.
// proxyPort is the local proxy port (0 is fine for MCP-only patching).
// The crust binary for MCP wrapping is os.Executable — the host binary
// (CLI or GUI) must support the "wrap" subcommand.
func PatchAgents(proxyPort int) {
	daemon.PatchAgentConfigs(proxyPort)
}

// RestoreAgents restores all patched agent configs to their originals.
func RestoreAgents() {
	daemon.RestoreAgentConfigs()
}
