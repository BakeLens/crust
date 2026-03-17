//go:build windows

package agentdetect

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func scanProcesses() ([]processInfo, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	var procs []processInfo
	err = windows.Process32First(snap, &pe)
	for err == nil {
		name := windows.UTF16ToString(pe.ExeFile[:])
		// Strip .exe suffix case-insensitively (Windows exe names can be any case)
		if len(name) > 4 && strings.EqualFold(name[len(name)-4:], ".exe") {
			name = name[:len(name)-4]
		}

		fullPath := queryFullPath(pe.ProcessID)

		procs = append(procs, processInfo{
			PID:  int(pe.ProcessID),
			Name: name,
			Path: fullPath,
		})
		err = windows.Process32Next(snap, &pe)
	}
	return procs, nil
}

// queryFullPath returns the full executable path for a process, or empty string on failure.
func queryFullPath(pid uint32) string {
	// PROCESS_QUERY_LIMITED_INFORMATION is sufficient for QueryFullProcessImageName
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	var buf [windows.MAX_PATH]uint16
	size := uint32(len(buf))
	err = windows.QueryFullProcessImageName(h, 0, &buf[0], &size)
	if err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}
