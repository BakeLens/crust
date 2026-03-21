package mcpdiscover

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestClientName(t *testing.T) {
	c := ClientDef{Client: ClientCursor}
	name := c.ClientName()
	if name == "" {
		t.Error("ClientName() returned empty string")
	}
	if name != "Cursor" {
		t.Errorf("ClientName() = %q, want %q", name, "Cursor")
	}
}

func TestBuiltinClients(t *testing.T) {
	clients := BuiltinClients()
	if len(clients) == 0 {
		t.Fatal("BuiltinClients() returned empty slice")
	}

	// Verify known clients are present.
	names := make(map[ClientType]bool)
	for _, c := range clients {
		names[c.Client] = true
	}

	want := []ClientType{ClientClaudeDesktop, ClientCursor, ClientWindsurf, ClientClaudeCode, ClientNeovim}
	for _, w := range want {
		if !names[w] {
			t.Errorf("BuiltinClients() missing %q", w)
		}
	}
}

func TestPatchClientDef_PatchAndRestore(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	original := `{
  "mcpServers": {
    "myserver": {
      "command": "npx",
      "args": ["-y", "my-mcp-server"]
    }
  }
}`
	if err := os.WriteFile(cfgPath, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}

	client := ClientDef{
		Client:     ClientCursor,
		ConfigPath: func() string { return cfgPath },
		ServersKey: "mcpServers",
		URLKeys:    []string{"url"},
	}

	crustBin := "/usr/local/bin/crust"

	// Patch
	if err := PatchClientDef(client, crustBin); err != nil {
		t.Fatalf("PatchClientDef: %v", err)
	}

	// Verify the file was patched.
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("unmarshal patched: %v", err)
	}
	var servers map[string]json.RawMessage
	if err := json.Unmarshal(root["mcpServers"], &servers); err != nil {
		t.Fatalf("unmarshal servers: %v", err)
	}
	var def map[string]any
	if err := json.Unmarshal(servers["myserver"], &def); err != nil {
		t.Fatal(err)
	}
	if def["command"] != crustBin {
		t.Errorf("patched command = %q, want %q", def["command"], crustBin)
	}

	// Verify backup was created.
	backupPath := cfgPath + mcpBackupSuffix
	if _, err := os.Stat(backupPath); err != nil {
		t.Fatalf("backup not created: %v", err)
	}

	// Restore
	if err := RestoreClientDef(client); err != nil {
		t.Fatalf("RestoreClientDef: %v", err)
	}

	// Verify original content restored.
	restored, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != original {
		t.Errorf("restored content does not match original:\ngot:  %s\nwant: %s", restored, original)
	}

	// Verify backup removed.
	if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
		t.Error("backup should be removed after RestoreClientDef")
	}
}

func TestPatchClientDef_EmptyPath(t *testing.T) {
	client := ClientDef{
		Client:     ClientCursor,
		ConfigPath: func() string { return "" },
		ServersKey: "mcpServers",
		URLKeys:    []string{"url"},
	}

	err := PatchClientDef(client, "/usr/local/bin/crust")
	if !errors.Is(err, ErrNothingPatched) {
		t.Errorf("expected ErrNothingPatched, got %v", err)
	}
}

func TestRestoreClientDef_EmptyPath(t *testing.T) {
	client := ClientDef{
		Client:     ClientCursor,
		ConfigPath: func() string { return "" },
		ServersKey: "mcpServers",
		URLKeys:    []string{"url"},
	}

	// Should be a no-op, no error.
	if err := RestoreClientDef(client); err != nil {
		t.Errorf("RestoreClientDef with empty path should return nil, got %v", err)
	}
}

func TestRestoreClientDef_NoBackup(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}

	client := ClientDef{
		Client:     ClientCursor,
		ConfigPath: func() string { return cfgPath },
		ServersKey: "mcpServers",
		URLKeys:    []string{"url"},
	}

	// No backup exists — should return nil (not an error).
	if err := RestoreClientDef(client); err != nil {
		t.Errorf("RestoreClientDef with no backup should return nil, got %v", err)
	}
}

func TestPatchClientDef_HTTPOnly_ReturnsErrNothingPatched(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{
		"mcpServers": {
			"remote": {"url": "https://example.com"}
		}
	}`), 0600); err != nil {
		t.Fatal(err)
	}

	client := ClientDef{
		Client:     ClientCursor,
		ConfigPath: func() string { return cfgPath },
		ServersKey: "mcpServers",
		URLKeys:    []string{"url"},
	}

	err := PatchClientDef(client, "/usr/local/bin/crust")
	if !errors.Is(err, ErrNothingPatched) {
		t.Errorf("expected ErrNothingPatched for HTTP-only config, got %v", err)
	}
}
