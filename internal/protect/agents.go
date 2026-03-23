package protect

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/BakeLens/crust/internal/daemon/registry"
)

// ListAgents returns a JSON array of installed/patched agents.
func ListAgents() string {
	type agentInfo struct {
		Name    string `json:"name"`
		Patched bool   `json:"patched"`
	}
	var agents []agentInfo
	for _, t := range registry.Default.Targets() {
		patched := registry.Default.IsPatched(t.Name())
		if !patched && !t.Installed() {
			continue
		}
		agents = append(agents, agentInfo{Name: t.Name(), Patched: patched})
	}
	if agents == nil {
		agents = []agentInfo{}
	}
	out, _ := json.Marshal(agents) //nolint:errcheck // struct slice cannot fail
	return string(out)
}

// EnableAgent patches a single agent by name.
func (inst *Instance) EnableAgent(name string) error {
	if inst == nil {
		return errors.New("protection is not running")
	}
	inst.mu.Lock()
	port := inst.port
	running := inst.running
	inst.mu.Unlock()

	if !running || port == 0 {
		return errors.New("protection is not running")
	}

	crustBin := ""
	if inst.cfg.Patcher != nil {
		crustBin = inst.cfg.Patcher.ResolveCrustBin()
	}
	for _, t := range registry.Default.Targets() {
		if t.Name() == name {
			if err := t.Patch(port, crustBin); err != nil {
				return err
			}
			registry.Default.MarkPatched(name)
			return nil
		}
	}
	return fmt.Errorf("agent %q not found", name)
}

// DisableAgent restores a single agent by name.
func (inst *Instance) DisableAgent(name string) error {
	for _, t := range registry.Default.Targets() {
		if t.Name() == name {
			if err := t.Restore(); err != nil {
				return err
			}
			registry.Default.MarkUnpatched(name)
			return nil
		}
	}
	return fmt.Errorf("agent %q not found", name)
}
