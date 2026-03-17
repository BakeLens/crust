//go:build windows

package registry

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
		// Strip .exe suffix for matching
		name = strings.TrimSuffix(name, ".exe")
		name = strings.TrimSuffix(name, ".EXE")
		procs = append(procs, processInfo{PID: int(pe.ProcessID), Name: name})
		err = windows.Process32Next(snap, &pe)
	}
	return procs, nil
}
