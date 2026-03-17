//go:build darwin

package agentdetect

import (
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func scanProcesses() ([]processInfo, error) {
	// ps -eo pid,args gives PID and full command path + arguments
	out, err := exec.Command("ps", "-eo", "pid,args").Output()
	if err != nil {
		return nil, err
	}
	var procs []processInfo
	for _, line := range strings.Split(string(out), "\n")[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Split: first field is PID, rest is full command with args
		idx := strings.IndexByte(line, ' ')
		if idx < 0 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(line[:idx]))
		if err != nil {
			continue
		}
		args := strings.TrimSpace(line[idx+1:])
		// Full path is the first token of args
		fullPath := args
		if spaceIdx := strings.IndexByte(args, ' '); spaceIdx > 0 {
			fullPath = args[:spaceIdx]
		}
		name := filepath.Base(fullPath)
		procs = append(procs, processInfo{PID: pid, Name: name, Path: fullPath})
	}
	return procs, nil
}
