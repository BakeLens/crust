package registry_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/BakeLens/crust/internal/daemon/registry"
)

// TestDefaultRegistryPopulated verifies that the init() in builtin.go registered
// at least OpenClaw (HTTP agent) and the 5 known MCP clients.
func TestDefaultRegistryPopulated(t *testing.T) {
	targets := registry.Default.Targets()
	if len(targets) == 0 {
		t.Fatal("Default registry is empty — builtin.go init() may not have run")
	}

	names := make(map[string]bool, len(targets))
	for _, tgt := range targets {
		names[tgt.Name()] = true
	}

	required := []string{
		"OpenClaw",
		"Claude Desktop",
		"Cursor",
		"Windsurf",
		"Claude Code",
		"Neovim (mcphub)",
	}
	for _, name := range required {
		if !names[name] {
			t.Errorf("expected target %q not found in Default registry", name)
		}
	}
}

// TestHTTPAgentPatchRestore exercises the full patch → verify → restore lifecycle
// using a temporary JSON config file.
func TestHTTPAgentPatchRestore(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	backup := cfgPath + ".crust-backup"

	original := map[string]any{
		"baseUrl": "https://api.openai.com",
		"apiKey":  "sk-test",
	}
	writeJSON(t, cfgPath, original)

	agent := &registry.HTTPAgent{
		AgentName:  "TestAgent",
		ConfigPath: func() string { return cfgPath },
		URLKey:     "baseUrl",
	}

	// Patch
	if err := agent.Patch(9090, ""); err != nil {
		t.Fatalf("Patch: %v", err)
	}

	// Verify config was patched
	patched := readJSON(t, cfgPath)
	if patched["baseUrl"] != "http://localhost:9090" {
		t.Errorf("baseUrl after patch = %q, want %q", patched["baseUrl"], "http://localhost:9090")
	}

	// Verify backup contains the original URL
	backupData, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("backup file missing: %v", err)
	}
	if string(backupData) != "https://api.openai.com" {
		t.Errorf("backup content = %q, want %q", backupData, "https://api.openai.com")
	}

	// Patch again — idempotent, backup must not be overwritten
	if err := agent.Patch(9090, ""); err != nil {
		t.Fatalf("second Patch: %v", err)
	}

	// Restore
	if err := agent.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// Verify config was restored
	restored := readJSON(t, cfgPath)
	if restored["baseUrl"] != "https://api.openai.com" {
		t.Errorf("baseUrl after restore = %q, want %q", restored["baseUrl"], "https://api.openai.com")
	}

	// Verify backup was removed
	if _, err := os.Stat(backup); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("backup file should be removed after Restore")
	}
}

// TestHTTPAgentMissingConfig verifies that Patch/Restore are no-ops when the
// config file does not exist.
func TestHTTPAgentMissingConfig(t *testing.T) {
	agent := &registry.HTTPAgent{
		AgentName:  "Ghost",
		ConfigPath: func() string { return filepath.Join(t.TempDir(), "nonexistent.json") },
		URLKey:     "baseUrl",
	}
	if err := agent.Patch(9090, ""); err == nil {
		t.Error("Patch on missing file should return error")
	}
	if err := agent.Restore(); err == nil {
		t.Error("Restore with no backup should return error")
	}
}

// TestHTTPAgentEmptyConfigPath verifies that Patch returns ErrNothingPatched
// when ConfigPath returns empty string (agent not installed on this machine),
// and Restore returns nil (nothing to undo).
func TestHTTPAgentEmptyConfigPath(t *testing.T) {
	agent := &registry.HTTPAgent{
		AgentName:  "NotInstalled",
		ConfigPath: func() string { return "" },
		URLKey:     "baseUrl",
	}
	if err := agent.Patch(9090, ""); !errors.Is(err, registry.ErrNothingPatched) {
		t.Errorf("Patch with empty path should return ErrNothingPatched, got: %v", err)
	}
	if err := agent.Restore(); err != nil {
		t.Errorf("Restore with empty path should be no-op, got: %v", err)
	}
}

// TestHTTPAgentMissingFileReturnsErrNothingPatched verifies that Patch returns
// ErrNothingPatched (not a generic error) when the config file doesn't exist.
func TestHTTPAgentMissingFileReturnsErrNothingPatched(t *testing.T) {
	agent := &registry.HTTPAgent{
		AgentName:  "Ghost",
		ConfigPath: func() string { return filepath.Join(t.TempDir(), "nonexistent.json") },
		URLKey:     "baseUrl",
	}
	err := agent.Patch(9090, "")
	if !errors.Is(err, registry.ErrNothingPatched) {
		t.Errorf("Patch on missing file should return ErrNothingPatched, got: %v", err)
	}
}

// TestPatchAllSkipsErrNothingPatched verifies that PatchAll does not mark
// targets as "patched" when they return ErrNothingPatched.
func TestPatchAllSkipsErrNothingPatched(t *testing.T) {
	r := &registry.Registry{}
	r.Register(&registry.FuncTarget{
		AgentName:   "Installed",
		PatchFunc:   func(_ int, _ string) error { return nil },
		RestoreFunc: func() error { return nil },
	})
	r.Register(&registry.FuncTarget{
		AgentName:   "NotInstalled",
		PatchFunc:   func(_ int, _ string) error { return registry.ErrNothingPatched },
		RestoreFunc: func() error { return nil },
	})

	r.PatchAll(9090, "")
	if !r.IsPatched("Installed") {
		t.Error("Installed should be patched")
	}
	if r.IsPatched("NotInstalled") {
		t.Error("NotInstalled should not be marked as patched")
	}
}

// TestFuncTargetDelegates verifies that FuncTarget calls its closures.
func TestFuncTargetDelegates(t *testing.T) {
	patched, restored := false, false

	ft := &registry.FuncTarget{
		AgentName:   "FuncAgent",
		PatchFunc:   func(_ int, _ string) error { patched = true; return nil },
		RestoreFunc: func() error { restored = true; return nil },
	}

	if ft.Name() != "FuncAgent" {
		t.Errorf("Name() = %q", ft.Name())
	}
	if err := ft.Patch(9090, "/usr/bin/crust"); err != nil {
		t.Errorf("Patch: %v", err)
	}
	if err := ft.Restore(); err != nil {
		t.Errorf("Restore: %v", err)
	}
	if !patched {
		t.Error("PatchFunc was not called")
	}
	if !restored {
		t.Error("RestoreFunc was not called")
	}
}

// TestRegistryPatchRestoreAll verifies PatchAll and RestoreAll delegate to targets.
func TestRegistryPatchRestoreAll(t *testing.T) {
	r := &registry.Registry{}

	calls := make([]string, 0, 4)
	r.Register(&registry.FuncTarget{
		AgentName:   "A",
		PatchFunc:   func(_ int, _ string) error { calls = append(calls, "patch-A"); return nil },
		RestoreFunc: func() error { calls = append(calls, "restore-A"); return nil },
	})
	r.Register(&registry.FuncTarget{
		AgentName:   "B",
		PatchFunc:   func(_ int, _ string) error { calls = append(calls, "patch-B"); return nil },
		RestoreFunc: func() error { calls = append(calls, "restore-B"); return nil },
	})

	r.PatchAll(9090, "")
	r.RestoreAll()

	want := []string{"patch-A", "patch-B", "restore-A", "restore-B"}
	if len(calls) != len(want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
	for i, c := range calls {
		if c != want[i] {
			t.Errorf("calls[%d] = %q, want %q", i, c, want[i])
		}
	}
}

func TestIsPatchedTracking(t *testing.T) {
	r := &registry.Registry{}
	r.Register(&registry.FuncTarget{
		AgentName:   "A",
		PatchFunc:   func(_ int, _ string) error { return nil },
		RestoreFunc: func() error { return nil },
	})
	r.Register(&registry.FuncTarget{
		AgentName:   "B",
		PatchFunc:   func(_ int, _ string) error { return errors.New("fail") },
		RestoreFunc: func() error { return nil },
	})

	if r.IsPatched("A") {
		t.Error("A should not be patched before PatchAll")
	}

	r.PatchAll(9090, "")
	if !r.IsPatched("A") {
		t.Error("A should be patched after PatchAll")
	}
	if r.IsPatched("B") {
		t.Error("B should not be patched (patch failed)")
	}

	r.RestoreAll()
	if r.IsPatched("A") {
		t.Error("A should not be patched after RestoreAll")
	}
}

// helpers

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("writeJSON marshal: %v", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("writeJSON write: %v", err)
	}
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("readJSON: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("readJSON unmarshal: %v", err)
	}
	return m
}
