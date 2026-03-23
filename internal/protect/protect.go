// Package protect provides a unified protection lifecycle for both the CLI
// daemon and the libcrust GUI app.
//
// Lifecycle:
//
//	Start():
//	  1. Start HTTP proxy (intercepts agent ↔ LLM traffic)
//	  2. Patch all agents (HTTP proxy configs, MCP wrappers, hooks)
//	  3. Start eval server (optional, for hook-based evaluation)
//
//	Stop():
//	  1. Restore all agents (revert configs, remove hooks)
//	  2. Stop eval server, remove port file
//
// All modifications are reversible. Stop runs via defer in RunServer,
// triggered by SIGINT/SIGTERM. If the daemon is killed with SIGKILL (or
// crashes), defers don't run — stopCleanup() in internal/daemon handles
// recovery when the user runs "crust stop".
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

// EvaluateFunc evaluates a tool call, returning JSON result.
type EvaluateFunc func(toolName, argsJSON string) string

// Config carries all dependencies — no package-level globals.
type Config struct {
	ProxyPort  int                                     // 0 = auto-assign
	StartProxy func(port int) (addr string, err error) // starts the HTTP proxy
	Patcher    AgentPatcher                            // patches agent configs
	EvalServer bool                                    // start TCP eval server
	Evaluate   EvaluateFunc                            // eval function for eval server
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

	// 2. Patch agent configs (including hooks — all registered in registry).
	if cfg.Patcher != nil {
		cfg.Patcher.PatchAgentConfigs(port)
	}

	// 3. Start eval server (optional).
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

// UninstallAll removes all Crust protection mechanisms from the system.
// Idempotent — safe to call from both Stop() (graceful shutdown) and
// daemon.stopCleanup() (SIGKILL recovery). Does not require a running
// Instance; works purely from on-disk state (backup files, settings.json).
//
// Calls registry.Default.RestoreAll() which iterates all registered targets:
// HTTP proxy agents, MCP config patches, and Claude Code hooks.
func UninstallAll() {
	registry.Default.RestoreAll()
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

	UninstallAll()
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
