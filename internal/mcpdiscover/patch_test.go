package mcpdiscover

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPatchConfigFile_BasicRoundTrip(t *testing.T) {
	dir := t.TempDir()
	original := `{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user"],
      "env": {"NODE_ENV": "production"}
    }
  }
}`
	path := writeFixture(t, dir, "config.json", original)
	crustBin := "/usr/local/bin/crust"

	client := ClientDef{
		Client:     ClientClaudeDesktop,
		ConfigPath: func() string { return path },
		ServersKey: "mcpServers",
		URLKeys:    []string{"url"},
	}

	// Patch
	n, err := patchConfigFile(path, client, crustBin)
	if err != nil {
		t.Fatalf("patch error: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 patched, got %d", n)
	}

	// Verify patched content
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	var servers map[string]json.RawMessage
	if err := json.Unmarshal(root["mcpServers"], &servers); err != nil {
		t.Fatal(err)
	}
	var def map[string]any
	if err := json.Unmarshal(servers["filesystem"], &def); err != nil {
		t.Fatal(err)
	}

	if def["command"] != crustBin {
		t.Errorf("command = %q, want %q", def["command"], crustBin)
	}

	args, ok := def["args"].([]any)
	if !ok {
		t.Fatal("args is not an array")
	}
	want := []string{"wrap", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/user"}
	if len(args) != len(want) {
		t.Fatalf("args len = %d, want %d", len(args), len(want))
	}
	for i, w := range want {
		if s, ok := args[i].(string); !ok || s != w {
			t.Errorf("args[%d] = %v, want %q", i, args[i], w)
		}
	}

	// Verify env preserved
	env, ok := def["env"].(map[string]any)
	if !ok {
		t.Fatal("env missing")
	}
	if env["NODE_ENV"] != "production" {
		t.Errorf("env NODE_ENV = %v, want %q", env["NODE_ENV"], "production")
	}

	// Verify backup exists
	backupPath := path + mcpBackupSuffix
	backupData, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("backup not created: %v", err)
	}
	if string(backupData) != original {
		t.Error("backup content does not match original")
	}

	// Restore
	if err := RestoreConfig(path); err != nil {
		t.Fatalf("restore error: %v", err)
	}

	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != original {
		t.Errorf("restored content does not match original")
	}

	// Backup should be removed
	if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
		t.Error("backup should be removed after restore")
	}
}

func TestPatchConfigFile_Idempotent(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "config.json", `{
		"mcpServers": {
			"fs": {
				"command": "npx",
				"args": ["server"]
			}
		}
	}`)

	client := ClientDef{
		Client:     ClientCursor,
		ConfigPath: func() string { return path },
		ServersKey: "mcpServers",
		URLKeys:    []string{"url"},
	}
	crustBin := "/usr/local/bin/crust"

	// Patch first time
	n1, err := patchConfigFile(path, client, crustBin)
	if err != nil {
		t.Fatal(err)
	}
	if n1 != 1 {
		t.Fatalf("first patch: expected 1, got %d", n1)
	}

	// Patch second time — should skip (already wrapped)
	n2, err := patchConfigFile(path, client, crustBin)
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 0 {
		t.Errorf("second patch: expected 0, got %d", n2)
	}
}

func TestPatchConfigFile_SkipsHTTP(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "config.json", `{
		"mcpServers": {
			"remote": {
				"url": "https://mcp.example.com"
			}
		}
	}`)

	client := ClientDef{
		Client:     ClientClaudeDesktop,
		ConfigPath: func() string { return path },
		ServersKey: "mcpServers",
		URLKeys:    []string{"url"},
	}

	n, err := patchConfigFile(path, client, "/usr/local/bin/crust")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("should not patch HTTP servers, got %d", n)
	}

	// No backup should be created
	if _, err := os.Stat(path + mcpBackupSuffix); !os.IsNotExist(err) {
		t.Error("backup should not be created when nothing is patched")
	}
}

func TestPatchConfigFile_PreservesNonServerKeys(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "config.json", `{
		"globalShortcut": "Ctrl+Space",
		"mcpServers": {
			"fs": {
				"command": "npx",
				"args": ["server"]
			}
		},
		"theme": "dark"
	}`)

	client := ClientDef{
		Client:     ClientClaudeDesktop,
		ConfigPath: func() string { return path },
		ServersKey: "mcpServers",
		URLKeys:    []string{"url"},
	}

	n, err := patchConfigFile(path, client, "/usr/local/bin/crust")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 patched, got %d", n)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	if root["globalShortcut"] != "Ctrl+Space" {
		t.Errorf("globalShortcut lost: %v", root["globalShortcut"])
	}
	if root["theme"] != "dark" {
		t.Errorf("theme lost: %v", root["theme"])
	}
}

func TestPatchConfigs_Integration(t *testing.T) {
	dir := t.TempDir()

	path1 := writeFixture(t, dir, "cursor.json", `{
		"mcpServers": {
			"fs": {"command": "npx", "args": ["server"]}
		}
	}`)
	path2 := writeFixture(t, dir, "claude.json", `{
		"mcpServers": {
			"db": {"command": "python", "args": ["db_server.py"]}
		}
	}`)

	clients := []ClientDef{
		{Client: ClientCursor, ConfigPath: func() string { return path1 }, ServersKey: "mcpServers", URLKeys: []string{"url"}},
		{Client: ClientClaudeCode, ConfigPath: func() string { return path2 }, ServersKey: "mcpServers", URLKeys: []string{"url"}},
	}

	result := PatchConfigsWithClients("/usr/local/bin/crust", clients)
	if result.Patched != 2 {
		t.Errorf("patched = %d, want 2", result.Patched)
	}
	if len(result.Errors) > 0 {
		t.Errorf("unexpected errors: %v", result.Errors)
	}

	// Restore all
	RestoreAllWithClients(clients)

	for _, p := range []string{path1, path2} {
		if _, err := os.Stat(p + mcpBackupSuffix); !os.IsNotExist(err) {
			t.Errorf("backup should be removed after RestoreAll: %s", p)
		}
	}
}

func TestRestoreConfig_NoBackup(t *testing.T) {
	err := RestoreConfig("/nonexistent/config.json")
	if err == nil {
		t.Error("expected error when no backup exists")
	}
}

func TestPatchConfigFile_MultipleStdioServers(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "config.json", `{
		"mcpServers": {
			"fs": {"command": "npx", "args": ["fs-server"]},
			"db": {"command": "python", "args": ["db.py"]},
			"remote": {"url": "https://example.com"}
		}
	}`)

	client := ClientDef{
		Client:     ClientCursor,
		ConfigPath: func() string { return path },
		ServersKey: "mcpServers",
		URLKeys:    []string{"url"},
	}

	n, err := patchConfigFile(path, client, "/usr/local/bin/crust")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("expected 2 patched (2 stdio, skip 1 http), got %d", n)
	}
}

func TestPatchConfigFile_SkipsAlreadyWrapped(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "config.json", `{
		"mcpServers": {
			"already": {
				"command": "/usr/local/bin/crust",
				"args": ["wrap", "--", "npx", "server"]
			},
			"unwrapped": {
				"command": "npx",
				"args": ["other-server"]
			}
		}
	}`)

	client := ClientDef{
		Client:     ClientCursor,
		ConfigPath: func() string { return path },
		ServersKey: "mcpServers",
		URLKeys:    []string{"url"},
	}

	n, err := patchConfigFile(path, client, "/usr/local/bin/crust")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected 1 patched (skip already wrapped), got %d", n)
	}
}

// FuzzMCPConfigPatch verifies that patchConfigFile never panics on arbitrary
// JSON config input and that patched output remains valid JSON.
func FuzzMCPConfigPatch(f *testing.F) {
	f.Add(`{"mcpServers":{"fs":{"command":"npx","args":["server"]}}}`)
	f.Add(`{"mcpServers":{"r":{"url":"https://example.com"}}}`)
	f.Add(`{"mcpServers":{}}`)
	f.Add(`{}`)
	f.Add(`{"mcpServers":{"x":{"command":""}}}`)
	f.Add(`{"mcpServers":{"x":{"command":null}}}`)
	f.Add(`{"mcpServers":{"x":{"command":"cmd","args":[1,2]}}}`)
	f.Add(`{"other":"value","mcpServers":{"fs":{"command":"npx"}}}`)
	f.Add(`{invalid}`)
	f.Add(``)

	f.Fuzz(func(t *testing.T, config string) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		if err := os.WriteFile(path, []byte(config), 0600); err != nil {
			t.Fatal(err)
		}

		// Use a simple fixed path to avoid JSON-escaping mismatches.
		crustBin := "/usr/local/bin/crust"

		client := ClientDef{
			Client:     ClientCursor,
			ConfigPath: func() string { return path },
			ServersKey: "mcpServers",
			URLKeys:    []string{"url"},
		}

		n, patchErr := patchConfigFile(path, client, crustBin)
		if patchErr != nil || n == 0 {
			return // invalid/empty config is fine
		}

		// If patching succeeded, output must be valid JSON.
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read patched file: %v", err)
		}
		if !json.Valid(data) {
			t.Fatalf("patched output is not valid JSON:\n%s", data)
		}

		// Patched servers must reference crust binary.
		if !strings.Contains(string(data), crustBin) {
			t.Fatal("patched output missing crust binary path")
		}
	})
}
