package daemon_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/BakeLens/crust/internal/daemon"
	"github.com/BakeLens/crust/internal/daemon/registry"
)

func TestResolveCrustBin(t *testing.T) {
	bin := daemon.ResolveCrustBin()
	if bin == "" {
		t.Fatal("ResolveCrustBin returned empty string")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("ResolveCrustBin returned non-existent path %q: %v", bin, err)
	}
}

// newAgent creates a test HTTPAgent pointing at the given config path.
func newAgent(path string) *registry.HTTPAgent {
	return &registry.HTTPAgent{
		AgentName:  "TestAgent",
		ConfigPath: func() string { return path },
		URLKey:     "baseUrl",
	}
}

func TestPatchAndRestore(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.json")

	initial := map[string]any{"baseUrl": "https://api.example.com", "model": "gpt-4"}
	writeJSON(t, configPath, initial)

	agent := newAgent(configPath)
	proxyURL := "http://localhost:9090"

	if err := agent.Patch(9090, ""); err != nil {
		t.Fatalf("patch: %v", err)
	}

	patched := readJSON(t, configPath)
	if got := patched["baseUrl"]; got != proxyURL {
		t.Errorf("after patch: baseUrl = %q, want %q", got, proxyURL)
	}
	if got := patched["model"]; got != "gpt-4" {
		t.Errorf("after patch: model = %q, want gpt-4", got)
	}

	backupPath := configPath + ".crust-backup"
	backup, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	if string(backup) != "https://api.example.com" {
		t.Errorf("backup = %q, want %q", backup, "https://api.example.com")
	}

	if err := agent.Restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}

	restored := readJSON(t, configPath)
	if got := restored["baseUrl"]; got != "https://api.example.com" {
		t.Errorf("after restore: baseUrl = %q, want %q", got, "https://api.example.com")
	}
	if got := restored["model"]; got != "gpt-4" {
		t.Errorf("after restore: model = %q, want gpt-4", got)
	}

	if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
		t.Error("backup file should be removed after restore")
	}
}

func TestPatchIdempotent(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.json")
	writeJSON(t, configPath, map[string]any{"baseUrl": "http://localhost:9090"})

	agent := newAgent(configPath)
	if err := agent.Patch(9090, ""); err != nil {
		t.Fatalf("patch: %v", err)
	}

	backupPath := configPath + ".crust-backup"
	if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
		t.Error("should not create backup when already patched")
	}
}

func TestPatchMissingFile(t *testing.T) {
	agent := newAgent("/nonexistent/path/config.json")
	if err := agent.Patch(9090, ""); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestRestoreNoBackup(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.json")
	_ = os.WriteFile(configPath, []byte(`{"baseUrl":"x"}`), 0o644)

	agent := newAgent(configPath)
	if err := agent.Restore(); err == nil {
		t.Error("expected error when no backup exists")
	}
}

func TestPatchEmptyOriginal(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.json")
	writeJSON(t, configPath, map[string]any{"model": "gpt-4"})

	agent := newAgent(configPath)
	if err := agent.Patch(9090, ""); err != nil {
		t.Fatalf("patch: %v", err)
	}

	patched := readJSON(t, configPath)
	if got := patched["baseUrl"]; got != "http://localhost:9090" {
		t.Errorf("baseUrl = %q, want http://localhost:9090", got)
	}

	if err := agent.Restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}

	restored := readJSON(t, configPath)
	if got := restored["baseUrl"]; got != "" {
		t.Errorf("after restore: baseUrl = %q, want empty", got)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("writeJSON: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("writeJSON write: %v", err)
	}
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("readJSON: %v", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		t.Fatalf("readJSON unmarshal: %v", err)
	}
	return obj
}
