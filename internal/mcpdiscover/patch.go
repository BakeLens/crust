package mcpdiscover

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/BakeLens/crust/internal/fileutil"
)

const mcpBackupSuffix = ".crust-mcp-backup"

// PatchResult summarizes what PatchConfigs did.
type PatchResult struct {
	Patched int
	Skipped int
	Errors  []PatchError
}

// PatchError records a non-fatal patch failure.
type PatchError struct {
	ConfigPath string
	Err        error
}

// PatchConfigs discovers all known MCP configs and rewrites stdio
// servers to route through "crust wrap".
func PatchConfigs(crustBin string) PatchResult {
	return PatchConfigsWithClients(crustBin, knownClients)
}

// PatchConfigsWithClients is the testable variant of PatchConfigs.
func PatchConfigsWithClients(crustBin string, clients []ClientDef) PatchResult {
	var result PatchResult
	for _, client := range clients {
		path := client.ConfigPath()
		if path == "" {
			continue
		}
		n, err := patchConfigFile(path, client, crustBin)
		if err != nil {
			if !os.IsNotExist(err) {
				result.Errors = append(result.Errors, PatchError{ConfigPath: path, Err: err})
			}
			continue
		}
		result.Patched += n
	}
	return result
}

// patchConfigFile rewrites stdio servers in a single config file.
// Returns the number of servers patched.
func patchConfigFile(path string, client ClientDef, crustBin string) (int, error) {
	if crustBin == "" {
		return 0, errors.New("crust binary path is empty — cannot wrap MCP servers")
	}
	root, servers, origData, err := readServersMap(path, client.ServersKey)
	if err != nil {
		return 0, err
	}
	if root == nil || servers == nil {
		return 0, nil
	}

	patched := 0
	for name, raw := range servers {
		var def map[string]any
		if err := json.Unmarshal(raw, &def); err != nil || def == nil {
			fmt.Fprintf(os.Stderr, "crust: mcp discover: skip %q: invalid JSON: %v\n", name, err)
			continue
		}

		cmd, ok := def["command"].(string)
		if !ok || cmd == "" {
			continue // HTTP/SSE transport — no command to wrap
		}

		args := extractArgs(def)
		if isCrustWrapped(cmd, args) {
			continue
		}

		// Build new args: ["wrap", "--", originalCmd, ...originalArgs]
		newArgs := make([]any, 0, 3+len(args))
		newArgs = append(newArgs, "wrap", "--", cmd)
		for _, a := range args {
			newArgs = append(newArgs, a)
		}

		def["command"] = crustBin
		def["args"] = newArgs

		newRaw, err := json.Marshal(def)
		if err != nil {
			fmt.Fprintf(os.Stderr, "crust: mcp discover: skip %q: marshal error: %v\n", name, err)
			continue
		}
		servers[name] = json.RawMessage(newRaw)
		patched++
	}

	if patched == 0 {
		return 0, nil
	}

	// Create whole-file backup (only if none exists yet).
	backupPath := path + mcpBackupSuffix
	if _, statErr := os.Stat(backupPath); statErr != nil {
		if !os.IsNotExist(statErr) {
			return 0, fmt.Errorf("cannot check backup %s: %w", backupPath, statErr)
		}
		if err := fileutil.SecureWriteFile(backupPath, origData); err != nil {
			return 0, err
		}
	}

	// Re-marshal servers back into root (compact; outer MarshalIndent handles formatting).
	newServers, err := json.Marshal(servers)
	if err != nil {
		return 0, err
	}
	root[client.ServersKey] = json.RawMessage(newServers)

	newData, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return 0, err
	}

	return patched, fileutil.SecureWriteFile(path, append(newData, '\n'))
}

// RestoreConfig restores a single config file from its backup.
func RestoreConfig(configPath string) error {
	backupPath := configPath + mcpBackupSuffix
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return err // no backup — nothing to restore
	}
	if err := fileutil.SecureWriteFile(configPath, data); err != nil {
		return err
	}
	return os.Remove(backupPath)
}

// RestoreAll restores every known client config from its backup.
// Returns the number of configs successfully restored.
func RestoreAll() int {
	return RestoreAllWithClients(knownClients)
}

// RestoreAllWithClients is the testable variant.
func RestoreAllWithClients(clients []ClientDef) int {
	restored := 0
	for _, client := range clients {
		path := client.ConfigPath()
		if path == "" {
			continue
		}
		if err := RestoreConfig(path); err != nil {
			if !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "crust: mcp discover: restore %s failed: %v\n", path, err)
			}
			continue
		}
		restored++
	}
	return restored
}

// PatchClientDef patches a single MCP client config to route its stdio servers
// through "crust wrap". Used by the daemon registry for per-client patching.
func PatchClientDef(c ClientDef, crustBin string) error {
	path := c.ConfigPath()
	if path == "" {
		return nil
	}
	_, err := patchConfigFile(path, c, crustBin)
	if os.IsNotExist(err) {
		return nil // config file absent — not an error
	}
	return err
}

// RestoreClientDef restores a single MCP client config from its backup.
// Used by the daemon registry for per-client restoration.
func RestoreClientDef(c ClientDef) error {
	path := c.ConfigPath()
	if path == "" {
		return nil
	}
	err := RestoreConfig(path)
	if os.IsNotExist(err) {
		return nil // no backup — nothing to restore
	}
	return err
}
