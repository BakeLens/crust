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
	// Go 1.22+ loop variables are per-iteration, so closures safely capture
	// the correct client definition for each iteration.
	for _, c := range mcpdiscover.BuiltinClients() {
		Register(&FuncTarget{
			AgentName: c.ClientName(),
			InstalledFunc: func() bool {
				path := c.ConfigPath()
				if path == "" {
					return false
				}
				_, err := os.Stat(path)
				return err == nil
			},
			PatchFunc:   func(_ int, bin string) error { return mcpdiscover.PatchClientDef(c, bin) },
			RestoreFunc: func() error { return mcpdiscover.RestoreClientDef(c) },
		})
	}
}
