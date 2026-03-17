//go:build linux

package registry

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func scanProcesses() ([]processInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var procs []processInfo
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(comm))
		if name != "" {
			procs = append(procs, processInfo{PID: pid, Name: name})
		}
	}
	return procs, nil
}
