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

		// Read full path from exe symlink (may fail for permission reasons)
		fullPath, err := os.Readlink(filepath.Join("/proc", e.Name(), "exe"))
		if err != nil {
			fullPath = ""
		}

		// Prefer basename from exe symlink (accurate, no length limit).
		// Fall back to /proc/[pid]/comm which is truncated to 15 chars
		// (TASK_COMM_LEN) and would miss names like "agentdetect.test".
		var name string
		if fullPath != "" {
			name = filepath.Base(fullPath)
		} else {
			comm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
			if err != nil {
				continue
			}
			name = strings.TrimSpace(string(comm))
		}
		if name == "" {
			continue
		}

		procs = append(procs, processInfo{PID: pid, Name: name, Path: fullPath})
	}
	return procs, nil
}
