package rules

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// TestMain enables the test binary to act as a shell worker subprocess.
// When invoked with _CRUST_SHELL_WORKER=1, it enters the worker loop
// instead of running tests.
func TestMain(m *testing.M) {
	if RunShellWorkerMain() {
		os.Exit(0)
	}
	code := m.Run()
	cleanupSharedPwshWorker()
	os.Exit(code)
}

func TestShellWorkerSubprocess(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot get test executable path: %v", err)
	}

	ext := NewExtractor()
	if err := ext.EnableSubprocessIsolation(context.Background(), exe); err != nil {
		t.Fatalf("EnableSubprocessIsolation failed: %v", err)
	}
	defer ext.Close()

	// Simple command extraction via worker
	info := ext.Extract("Bash", json.RawMessage(`{"command":"cat /etc/passwd"}`))
	if len(info.Paths) == 0 {
		t.Error("expected paths from worker extraction, got none")
	}
	if !slices.Contains(info.Paths, "/etc/passwd") {
		t.Errorf("expected /etc/passwd in paths, got %v", info.Paths)
	}

	// Pipeline extraction via worker
	info2 := ext.Extract("Bash", json.RawMessage(`{"command":"cat /etc/shadow | grep root > /tmp/out"}`))
	if len(info2.Paths) == 0 {
		t.Error("expected paths from pipeline extraction, got none")
	}

	// Process substitution: AST fallback extracts commands and paths
	info3 := ext.Extract("Bash", json.RawMessage(`{"command":"diff <(cat /etc/passwd) <(cat /etc/shadow)"}`))
	if info3.Evasive {
		t.Errorf("process substitution should not be evasive, got reason: %s", info3.EvasiveReason)
	}
	if !slices.Contains(info3.Paths, "/etc/passwd") || !slices.Contains(info3.Paths, "/etc/shadow") {
		t.Errorf("expected /etc/passwd and /etc/shadow in paths, got %v", info3.Paths)
	}
}

func TestShellWorkerCrashRecovery(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot get test executable path: %v", err)
	}

	ext := NewExtractor()
	if err := ext.EnableSubprocessIsolation(context.Background(), exe); err != nil {
		t.Fatalf("EnableSubprocessIsolation failed: %v", err)
	}
	defer ext.Close()

	// Coproc: AST fallback extracts the inner command and paths
	info := ext.Extract("Bash", json.RawMessage(`{"command":"coproc cat /etc/shadow"}`))
	if info.Evasive {
		t.Errorf("coproc should not be evasive, got reason: %s", info.EvasiveReason)
	}
	if !slices.Contains(info.Paths, "/etc/shadow") {
		t.Errorf("expected /etc/shadow in paths, got %v", info.Paths)
	}

	// After a potential crash, the next command should still work
	info2 := ext.Extract("Bash", json.RawMessage(`{"command":"cat /tmp/test"}`))
	if len(info2.Paths) == 0 {
		t.Error("expected paths after crash recovery, got none")
	}
}
