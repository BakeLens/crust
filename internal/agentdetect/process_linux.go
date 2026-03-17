//go:build linux

package agentdetect

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

		// Read exe name from comm
		comm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(comm))
		if name == "" {
			continue
		}

		// Read full path from exe symlink (may fail for permission reasons)
		fullPath, _ := os.Readlink(filepath.Join("/proc", e.Name(), "exe"))

		procs = append(procs, processInfo{PID: pid, Name: name, Path: fullPath})
	}
	return procs, nil
}
