package monitor

import (
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/BakeLens/crust/internal/daemon/registry"
)

const protectWatchInterval = 1 * time.Second

// protectSnapshot is a comparable representation of protection status.
type protectSnapshot struct {
	Active        bool   `json:"active"`
	ProxyPort     int    `json:"proxy_port"`
	PatchedAgents string // sorted, comma-joined for comparison (not in JSON)
}

// protectStatus is the JSON payload for protect changes.
type protectStatus struct {
	Active        bool     `json:"active"`
	ProxyPort     int      `json:"proxy_port"`
	PatchedAgents []string `json:"patched_agents"`
}

// protectStateFuncVal stores the function that returns current protect state.
// Access via atomic.Value for concurrent safety.
var protectStateFuncVal atomic.Value // stores func() (bool, int)

// SetProtectStateFunc sets the function used to read the current protection
// state (active flag and proxy port). This breaks the import cycle between
// internal/monitor and pkg/libcrust/protect.go.
// Safe to call from any goroutine.
func SetProtectStateFunc(fn func() (active bool, port int)) {
	protectStateFuncVal.Store(fn)
}

// loadProtectStateFunc returns the current protect state function, or nil.
func loadProtectStateFunc() func() (bool, int) {
	v := protectStateFuncVal.Load()
	if v == nil {
		return nil
	}
	return v.(func() (bool, int))
}

// runProtectWatcher checks protection status every 1 second.
// Emits ChangeProtect only when the status differs from the previous check.
func (m *Monitor) runProtectWatcher(prev protectSnapshot) {
	defer m.wg.Done()
	ticker := time.NewTicker(protectWatchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			curr := takeProtectSnapshot()
			if curr != prev {
				status := getProtectSnapshot()
				m.emit(ChangeProtect, status)
				prev = curr
			}
		}
	}
}

// getProtectSnapshot returns the current protection status as a JSON-friendly struct.
func getProtectSnapshot() protectStatus {
	active, port := false, 0
	if fn := loadProtectStateFunc(); fn != nil {
		active, port = fn()
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

	return protectStatus{
		Active:        active,
		ProxyPort:     port,
		PatchedAgents: patched,
	}
}

// takeProtectSnapshot returns a comparable snapshot of the current protection state.
func takeProtectSnapshot() protectSnapshot {
	status := getProtectSnapshot()
	sorted := make([]string, len(status.PatchedAgents))
	copy(sorted, status.PatchedAgents)
	sort.Strings(sorted)
	return protectSnapshot{
		Active:        status.Active,
		ProxyPort:     status.ProxyPort,
		PatchedAgents: strings.Join(sorted, ","),
	}
}
