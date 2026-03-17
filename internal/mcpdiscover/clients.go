package mcpdiscover

import (
	"os"
	"path/filepath"
	"runtime"
)

// ClientDef describes how to find and parse one MCP client's config.
// Add new MCP clients by appending a ClientDef to knownClients below.
type ClientDef struct {
	Client     ClientType
	ConfigPath func() string // returns the config file path (empty if unknown)
	ServersKey string        // JSON key holding the servers map ("mcpServers" or "servers")
	URLKeys    []string      // JSON keys for HTTP server URL ("url", "serverUrl")
}

// ClientName returns the human-readable client name.
func (c ClientDef) ClientName() string { return string(c.Client) }

// homeJoin returns filepath.Join(home, elems...) or "" if home dir is unavailable.
func homeJoin(elems ...string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(append([]string{home}, elems...)...)
}

// knownClients lists MCP clients whose configs are scanned for auto-discovery.
var knownClients = []ClientDef{
	{
		Client: ClientClaudeDesktop,
		ConfigPath: func() string {
			switch runtime.GOOS {
			case "darwin":
				return homeJoin("Library", "Application Support", "Claude", "claude_desktop_config.json")
			case "windows":
				if appdata := os.Getenv("APPDATA"); appdata != "" {
					return filepath.Join(appdata, "Claude", "claude_desktop_config.json")
				}
				return ""
			default:
				return homeJoin(".config", "Claude", "claude_desktop_config.json")
			}
		},
		ServersKey: "mcpServers",
		URLKeys:    []string{"url"},
	},
	{
		Client:     ClientCursor,
		ConfigPath: func() string { return homeJoin(".cursor", "mcp.json") },
		ServersKey: "mcpServers",
		URLKeys:    []string{"url"},
	},
	{
		Client:     ClientWindsurf,
		ConfigPath: func() string { return homeJoin(".codeium", "windsurf", "mcp_config.json") },
		ServersKey: "mcpServers",
		URLKeys:    []string{"url", "serverUrl"},
	},
	{
		Client:     ClientClaudeCode,
		ConfigPath: func() string { return homeJoin(".claude.json") },
		ServersKey: "mcpServers",
		URLKeys:    []string{"url"},
	},
	{
		Client:     ClientNeovim,
		ConfigPath: func() string { return homeJoin(".config", "mcphub", "servers.json") },
		ServersKey: "mcpServers",
		URLKeys:    []string{"url"},
	},
}

// BuiltinClients returns all built-in MCP client definitions.
// Used by the daemon registry to register each client as a patch target.
func BuiltinClients() []ClientDef { return knownClients }
