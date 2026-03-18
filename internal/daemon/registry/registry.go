// Package registry manages all config targets that Crust patches on daemon
// start and restores on daemon stop.
//
// # Adding a new HTTP-proxy agent
//
// Add one [HTTPAgent] entry to the init() function in builtin.go:
//
//	Register(&HTTPAgent{
//	    AgentName:  "MyAgent",
//	    ConfigPath: func() string { home, _ := os.UserHomeDir(); return filepath.Join(home, ".myagent", "config.json") },
//	    URLKey:     "baseUrl",  // JSON key holding the API endpoint
//	    PathSuffix: "",         // or "/v1" for OpenAI-compat endpoints
//	})
//
// # Adding a new MCP client
//
// Add one ClientDef entry to knownClients in internal/mcpdiscover/clients.go.
// It is automatically included in the registry via BuiltinClients().
//
// # Process detection
//
// Process detection has been moved to the internal/agentdetect package.
// See [agentdetect.Detect] for scanning running AI agent processes.
package registry

import (
	"errors"
	"sync"

	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/mcpdiscover"
)

var log = logger.New("registry")

// Default is the global registry used by the daemon.
var Default = &Registry{}

// Registry holds all patch targets and provides PatchAll/RestoreAll operations.
type Registry struct {
	mu      sync.RWMutex
	targets []Target
	patched map[string]bool
}

// Register adds a target to the registry.
func (r *Registry) Register(t Target) { r.targets = append(r.targets, t) }

// Register adds a target to the Default registry.
// Called from init() in builtin.go for all built-in targets.
func Register(t Target) { Default.Register(t) }

// PatchAll routes every registered target through the Crust proxy.
// proxyPort is the listening port; crustBin is the resolved crust binary path.
// Errors are non-fatal — a failed patch is logged and skipped.
func (r *Registry) PatchAll(proxyPort int, crustBin string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.patched == nil {
		r.patched = make(map[string]bool)
	}
	for _, t := range r.targets {
		if err := t.Patch(proxyPort, crustBin); err != nil {
			if !errors.Is(err, mcpdiscover.ErrNothingPatched) {
				log.Warn("patch %s: %v", t.Name(), err)
			}
		} else {
			r.patched[t.Name()] = true
		}
	}
}

// RestoreAll restores every registered target to its original config.
// Best-effort: errors are logged and skipped.
func (r *Registry) RestoreAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.targets {
		if err := t.Restore(); err != nil {
			log.Warn("restore %s: %v", t.Name(), err)
		}
	}
	r.patched = nil
}

// IsPatched reports whether the named target was successfully patched.
func (r *Registry) IsPatched(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.patched[name]
}

// Targets returns the registered targets (for testing).
func (r *Registry) Targets() []Target { return r.targets }
