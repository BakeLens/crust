package daemon

import (
	"os"
	"path/filepath"

	"github.com/BakeLens/crust/internal/daemon/registry"
	"github.com/BakeLens/crust/internal/logger"
)

var log = logger.New("daemon")

// PatchAgentConfigs routes all registered agents through the Crust proxy.
// The crust binary for MCP wrapping is the current executable (os.Executable).
// This works for both the CLI daemon ("crust") and the GUI ("crust-app"),
// since both support the "wrap" subcommand.
func PatchAgentConfigs(proxyPort int) {
	crustBin := ResolveCrustBin()
	if crustBin == "" {
		log.Warn("cannot resolve executable path, skipping agent patching")
		return
	}
	log.Info("patching agents with binary: %s", crustBin)
	registry.Default.PatchAll(proxyPort, crustBin)
}

// RestoreAgentConfigs restores all patched agent configs to their originals.
// Called on daemon shutdown and by crust stop when the daemon has already exited.
func RestoreAgentConfigs() {
	registry.Default.RestoreAll()
}

// ResolveCrustBin returns the absolute path to the current executable.
// Both the CLI ("crust") and GUI ("crust-app") support the "wrap" subcommand,
// so the running binary is always the correct wrapper for MCP config patching.
func ResolveCrustBin() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return exe
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return resolved
	}
	return abs
}
