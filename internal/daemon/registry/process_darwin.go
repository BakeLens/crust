//go:build darwin

package registry

import (
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func scanProcesses() ([]processInfo, error) {
	out, err := exec.Command("ps", "-eo", "pid,comm").Output()
	if err != nil {
		return nil, err
	}
	var procs []processInfo
	for _, line := range strings.Split(string(out), "\n")[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, " ", 2)
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(fields[0]))
		if err != nil {
			continue
		}
		name := filepath.Base(strings.TrimSpace(fields[1]))
		if name != "" {
			procs = append(procs, processInfo{PID: pid, Name: name})
		}
	}
	return procs, nil
}
