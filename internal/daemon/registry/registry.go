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
// Targets can optionally implement the [ProcessDetectable] interface to enable
// process scanning via [Registry.Detect]. For [HTTPAgent], set ExeNames when
// registering:
//
//	Register(&HTTPAgent{
//	    AgentName:  "MyAgent",
//	    ConfigPath: func() string { ... },
//	    URLKey:     "baseUrl",
//	    ExeNames:   []string{"myagent", "myagent.exe"},
//	})
//
// For [FuncTarget], set ExeNames in the struct literal. Targets without
// ExeNames are silently skipped during process detection.
package registry

import (
	"strings"

	"github.com/BakeLens/crust/internal/logger"
)

var log = logger.New("registry")

// Default is the global registry used by the daemon.
var Default = &Registry{}

// Registry holds all patch targets and provides PatchAll/RestoreAll operations.
type Registry struct {
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
	if r.patched == nil {
		r.patched = make(map[string]bool)
	}
	for _, t := range r.targets {
		if err := t.Patch(proxyPort, crustBin); err != nil {
			log.Warn("patch %s: %v", t.Name(), err)
		} else {
			r.patched[t.Name()] = true
		}
	}
}

// RestoreAll restores every registered target to its original config.
// Best-effort: errors are logged and skipped.
func (r *Registry) RestoreAll() {
	for _, t := range r.targets {
		if err := t.Restore(); err != nil {
			log.Warn("restore %s: %v", t.Name(), err)
		}
	}
	r.patched = nil
}

// IsPatched reports whether the named target was successfully patched.
func (r *Registry) IsPatched(name string) bool {
	if r.patched == nil {
		return false
	}
	return r.patched[name]
}

// Targets returns the registered targets (for testing).
func (r *Registry) Targets() []Target { return r.targets }

// DetectedAgent represents a running or configured AI agent.
type DetectedAgent struct {
	Name        string `json:"name"`
	Status      string `json:"status"` // "protected", "running", "configured"
	PIDs        []int  `json:"pids"`
	ProcessName string `json:"process_name,omitempty"`
}

// Detect scans for running AI agent processes and returns their status.
func (r *Registry) Detect() []DetectedAgent {
	procs, err := scanProcesses()
	if err != nil {
		log.Warn("process scan failed: %v", err)
		procs = nil
	}

	var agents []DetectedAgent
	for _, t := range r.targets {
		pd, ok := t.(ProcessDetectable)
		if !ok {
			continue
		}
		exeNames := pd.ProcessNames()
		if len(exeNames) == 0 {
			continue
		}

		// Find matching PIDs
		var pids []int
		var matchedName string
		for _, p := range procs {
			for _, exe := range exeNames {
				if strings.EqualFold(p.Name, exe) {
					pids = append(pids, p.PID)
					if matchedName == "" {
						matchedName = p.Name
					}
					break
				}
			}
		}

		patched := r.IsPatched(t.Name())

		if len(pids) > 0 && patched {
			agents = append(agents, DetectedAgent{Name: t.Name(), Status: "protected", PIDs: pids, ProcessName: matchedName})
		} else if len(pids) > 0 {
			agents = append(agents, DetectedAgent{Name: t.Name(), Status: "running", PIDs: pids, ProcessName: matchedName})
		} else if patched {
			agents = append(agents, DetectedAgent{Name: t.Name(), Status: "configured", PIDs: nil, ProcessName: ""})
		}
	}
	return agents
}
