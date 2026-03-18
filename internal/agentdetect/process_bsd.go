//go:build darwin || freebsd || openbsd || netbsd || dragonfly

package agentdetect

import (
	"context"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func scanProcesses() ([]processInfo, error) {
	// ps -eo pid,args gives PID and full command path + arguments
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ps", "-eo", "pid,args").Output()
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
		before, after, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(before))
		if err != nil {
			continue
		}
		args := strings.TrimSpace(after)
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
