//go:build libcrust

package libcrust

import (
	"fmt"

	"github.com/BakeLens/crust/internal/daemon"
	"github.com/BakeLens/crust/internal/protect"
)

// protectInst holds the running protection instance. Instance methods are
// thread-safe, so no additional mutex is needed here.
var protectInst *protect.Instance

// StartProtect starts the full protection stack.
func StartProtect() (int, error) {
	if protectInst != nil && protectInst.Running() {
		return protectInst.Port(), nil
	}

	inst, err := protect.Start(protect.Config{
		ProxyPort: 0,
		StartProxy: func(port int) (string, error) {
			if err := StartProxy(port, "", "", ""); err != nil {
				return "", err
			}
			addr := ProxyAddress()
			if addr == "" {
				StopProxy()
				return "", fmt.Errorf("proxy started but address is empty")
			}
			return addr, nil
		},
		Patcher:      daemon.Patcher{},
		InstallHooks: true,
		Hooks:        claudeHookInstaller{},
		EvalServer:   true,
		Evaluate:     Evaluate,
	})
	if err != nil {
		return 0, err
	}
	protectInst = inst
	return inst.Port(), nil
}

// StopProtect tears down the full protection stack.
func StopProtect() {
	if protectInst != nil {
		protectInst.Stop()
		protectInst = nil
	}
	StopProxy()
}

// ProtectPort returns the proxy port, or 0 if not running.
func ProtectPort() int { return protectInst.Port() }

// ProtectStatus returns the current protection status as JSON.
func ProtectStatus() string { return protectInst.Status() }

// ListAgents returns a JSON array of installed/patched agents.
func ListAgents() string { return protect.ListAgents() }

// EnableAgent patches a single agent by name.
func EnableAgent(name string) error { return protectInst.EnableAgent(name) }

// DisableAgent restores a single agent by name.
func DisableAgent(name string) error { return protectInst.DisableAgent(name) }

// EvaluateViaRunningInstance evaluates via a running instance.
func EvaluateViaRunningInstance(hookInput string) string {
	return protect.EvaluateViaRunningInstance(hookInput)
}

// ReadPortFile reads the eval port from ~/.crust/protect.port.
func ReadPortFile() int { return protect.ReadPortFile() }

// claudeHookInstaller wraps hooks.go functions.
type claudeHookInstaller struct{}

func (claudeHookInstaller) Install(crustBin string) error {
	cleanupStaleHooksFile()
	return InstallClaudeHook(crustBin)
}

func (claudeHookInstaller) Uninstall() error {
	return UninstallClaudeHook()
}
