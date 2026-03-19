package monitor

import (
	"sort"
	"time"

	"github.com/BakeLens/crust/internal/agentdetect"
)

const agentScanInterval = 5 * time.Second

// agentSnapshot is a comparable representation of an agent's state.
type agentSnapshot struct {
	Name   string
	Status string
	PIDs   string // sorted, comma-joined for comparison
}

// runAgentScanner polls for agent process changes every 5 seconds.
// Emits ChangeAgents only when the agent list or status differs from the previous poll.
func (m *Monitor) runAgentScanner(prev []agentSnapshot) {
	defer m.wg.Done()
	ticker := time.NewTicker(agentScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			agents := detectCurrentAgents()
			curr := snapshotAgents(agents)
			if !agentSnapshotsEqual(prev, curr) {
				m.emit(ChangeAgents, agents)
				prev = curr
			}
		}
	}
}

// detectCurrentAgents returns the current list of detected agents.
func detectCurrentAgents() []agentdetect.DetectedAgent {
	return agentdetect.Detect()
}

// snapshotAgents converts a list of detected agents into a comparable snapshot.
func snapshotAgents(agents []agentdetect.DetectedAgent) []agentSnapshot {
	snap := make([]agentSnapshot, len(agents))
	for i, a := range agents {
		snap[i] = agentSnapshot{
			Name:   a.Name,
			Status: a.Status,
			PIDs:   sortedPIDs(a.PIDs),
		}
	}
	// Sort by name for stable comparison.
	sort.Slice(snap, func(i, j int) bool { return snap[i].Name < snap[j].Name })
	return snap
}

// sortedPIDs returns a stable string representation of PIDs for comparison.
func sortedPIDs(pids []int) string {
	if len(pids) == 0 {
		return ""
	}
	sorted := make([]int, len(pids))
	copy(sorted, pids)
	sort.Ints(sorted)
	buf := make([]byte, 0, len(sorted)*6)
	for i, p := range sorted {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = appendInt(buf, p)
	}
	return string(buf)
}

// appendInt appends an integer as decimal digits to buf.
func appendInt(buf []byte, n int) []byte {
	if n == 0 {
		return append(buf, '0')
	}
	if n < 0 {
		buf = append(buf, '-')
		n = -n
	}
	start := len(buf)
	for n > 0 {
		buf = append(buf, byte('0'+n%10))
		n /= 10
	}
	// Reverse the digits.
	for i, j := start, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return buf
}

// agentSnapshotsEqual compares two sorted snapshots for equality.
func agentSnapshotsEqual(a, b []agentSnapshot) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
