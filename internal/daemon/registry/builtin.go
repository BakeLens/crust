package registry

import (
	"os"
	"path/filepath"

	"github.com/BakeLens/crust/internal/mcpdiscover"
)

func init() {
	// ── HTTP proxy agents ─────────────────────────────────────────────────────
	// To add a new agent that uses HTTP URL replacement, append an HTTPAgent here.
	Register(&HTTPAgent{
		AgentName: "OpenClaw",
		ConfigPath: func() string {
			home, err := os.UserHomeDir()
			if err != nil || home == "" {
				return ""
			}
			return filepath.Join(home, ".openclaw", "openclaw.json")
		},
		URLKey: "baseUrl",
	})

	// ── MCP clients ───────────────────────────────────────────────────────────
	// New MCP clients are added to internal/mcpdiscover/clients.go and
	// automatically appear here via BuiltinClients().
	for _, c := range mcpdiscover.BuiltinClients() {
		Register(&FuncTarget{
			AgentName:   c.ClientName(),
			PatchFunc:   func(_ int, bin string) error { return mcpdiscover.PatchClientDef(c, bin) },
			RestoreFunc: func() error { return mcpdiscover.RestoreClientDef(c) },
		})
	}
}
