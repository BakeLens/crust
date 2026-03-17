package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestScanProcessesReturnsCurrentProcess verifies that scanProcesses() finds at
// least the current test process (the go test binary itself).
func TestScanProcessesReturnsCurrentProcess(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	testBin := filepath.Base(exe)
	testBin = strings.TrimSuffix(testBin, ".exe")
	testBin = strings.TrimSuffix(testBin, ".EXE")

	procs, err := scanProcesses()
	if err != nil {
		t.Fatalf("scanProcesses: %v", err)
	}

	found := false
	for _, p := range procs {
		if strings.EqualFold(p.Name, testBin) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("scanProcesses did not find current test process %q", testBin)
	}
}

// TestScanProcessesNotEmpty verifies scanProcesses() returns a non-empty list.
func TestScanProcessesNotEmpty(t *testing.T) {
	procs, err := scanProcesses()
	if err != nil {
		t.Fatalf("scanProcesses: %v", err)
	}
	if len(procs) == 0 {
		t.Fatal("scanProcesses returned empty list, expected at least one process")
	}
}

// TestScanProcessesValidPIDs verifies all returned PIDs are >= 0.
// PID 0 is the System Idle Process on Windows, so we allow it.
func TestScanProcessesValidPIDs(t *testing.T) {
	procs, err := scanProcesses()
	if err != nil {
		t.Fatalf("scanProcesses: %v", err)
	}
	for _, p := range procs {
		if p.PID < 0 {
			t.Errorf("invalid PID %d for process %q", p.PID, p.Name)
		}
	}
}

// TestScanProcessesValidNames verifies all returned names are non-empty strings.
// PID 0 (System Idle Process) may have an empty name on Windows, so we skip it.
func TestScanProcessesValidNames(t *testing.T) {
	procs, err := scanProcesses()
	if err != nil {
		t.Fatalf("scanProcesses: %v", err)
	}
	for _, p := range procs {
		if p.PID == 0 {
			continue // System Idle Process on Windows may have empty name
		}
		if p.Name == "" {
			t.Errorf("empty name for PID %d", p.PID)
		}
	}
}
