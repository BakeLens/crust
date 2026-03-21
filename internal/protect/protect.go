// Package protect provides a unified protection lifecycle for both the CLI
// daemon and the libcrust GUI app.
package protect

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/BakeLens/crust/internal/daemon/registry"
	"github.com/BakeLens/crust/internal/logger"
)

var log = logger.New("protect")

// AgentPatcher patches and restores agent configs.
type AgentPatcher interface {
	PatchAgentConfigs(proxyPort int)
	RestoreAgentConfigs()
	ResolveCrustBin() string
}

// HookInstaller installs/uninstalls Claude Code PreToolUse hooks.
type HookInstaller interface {
	Install(crustBin string) error
	Uninstall() error
}

// EvaluateFunc evaluates a tool call, returning JSON result.
type EvaluateFunc func(toolName, argsJSON string) string

// Config carries all dependencies — no package-level globals.
type Config struct {
	ProxyPort    int                                     // 0 = auto-assign
	StartProxy   func(port int) (addr string, err error) // starts the HTTP proxy
	Patcher      AgentPatcher                            // patches agent configs
	InstallHooks bool                                    // install Claude Code hooks
	Hooks        HookInstaller                           // hook installer
	EvalServer   bool                                    // start TCP eval server
	Evaluate     EvaluateFunc                            // eval function for eval server
}

// Instance represents a running protection instance.
type Instance struct {
	mu       sync.Mutex
	running  bool
	port     int
	evalLn   net.Listener
	evalPort int
	cfg      Config
}

// Start starts the protection stack. Returns an Instance for lifecycle management.
func Start(cfg Config) (*Instance, error) {
	if cfg.StartProxy == nil {
		return nil, errors.New("StartProxy function is required")
	}

	// 1. Start proxy.
	addr, err := cfg.StartProxy(cfg.ProxyPort)
	if err != nil {
		return nil, fmt.Errorf("start proxy: %w", err)
	}
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("parse proxy address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("parse port %q: %w", portStr, err)
	}

	// 2. Patch agent configs.
	if cfg.Patcher != nil {
		cfg.Patcher.PatchAgentConfigs(port)
	}

	// 3. Install hooks (optional).
	if cfg.InstallHooks && cfg.Hooks != nil && cfg.Patcher != nil {
		crustBin := cfg.Patcher.ResolveCrustBin()
		if crustBin != "" {
			if err := cfg.Hooks.Install(crustBin); err != nil {
				log.Warn("install claude hook: %v", err)
			} else {
				registry.Default.MarkPatched("Claude Code")
			}
		}
	}

	// 4. Start eval server (optional).
	inst := &Instance{running: true, port: port, cfg: cfg}
	if cfg.EvalServer && cfg.Evaluate != nil {
		evalPort, err := inst.startEvalServer()
		if err != nil {
			log.Warn("start eval server: %v", err)
		} else {
			inst.evalPort = evalPort
			writePortFile(evalPort)
		}
	}

	return inst, nil
}

// Stop tears down the protection stack.
func (inst *Instance) Stop() {
	if inst == nil {
		return
	}
	inst.mu.Lock()
	defer inst.mu.Unlock()

	if !inst.running {
		return
	}

	if inst.cfg.Hooks != nil {
		if err := inst.cfg.Hooks.Uninstall(); err != nil {
			log.Warn("uninstall claude hook: %v", err)
		}
	}
	if inst.cfg.Patcher != nil {
		inst.cfg.Patcher.RestoreAgentConfigs()
	}

	inst.stopEvalServer()
	removePortFile()
	inst.running = false
	inst.port = 0
	inst.evalPort = 0
}

// Port returns the proxy port, or 0 if not running.
func (inst *Instance) Port() int {
	if inst == nil {
		return 0
	}
	inst.mu.Lock()
	defer inst.mu.Unlock()
	return inst.port
}

// Running returns whether protection is active.
func (inst *Instance) Running() bool {
	if inst == nil {
		return false
	}
	inst.mu.Lock()
	defer inst.mu.Unlock()
	return inst.running
}

// Status returns the current protection status as JSON.
func (inst *Instance) Status() string {
	active := false
	port := 0
	if inst != nil {
		inst.mu.Lock()
		active = inst.running
		port = inst.port
		inst.mu.Unlock()
	}

	var patched []string
	for _, t := range registry.Default.Targets() {
		if registry.Default.IsPatched(t.Name()) {
			patched = append(patched, t.Name())
		}
	}
	if patched == nil {
		patched = []string{}
	}

	out, _ := json.Marshal(map[string]any{ //nolint:errcheck // map[string]any cannot fail
		"active":         active,
		"proxy_port":     port,
		"patched_agents": patched,
	})
	return string(out)
}
