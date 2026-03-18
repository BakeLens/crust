package agentdetect

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/BakeLens/crust/internal/daemon/registry"
	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/pathutil"
)

var log = logger.New("agentdetect")

// AgentSignature defines how to identify a running AI agent.
type AgentSignature struct {
	Name         string   // human-readable name, e.g. "Claude Code"
	ExeNames     []string // executable basenames (case-sensitive, without .exe)
	PathPatterns []string // substrings to match in full exe path (e.g. ".local/bin/claude", "WindowsApps/Claude")
}

// DetectedAgent represents a detected AI agent with its status.
// PIDs are a point-in-time snapshot; processes may exit before display.
type DetectedAgent struct {
	Name        string `json:"name"`
	Status      string `json:"status"` // "protected", "running", "configured"
	PIDs        []int  `json:"pids"`
	ProcessName string `json:"process_name,omitempty"`
	ExePath     string `json:"exe_path,omitempty"`
}

// KnownAgents lists all AI agents we can detect.
//
// PathPatterns use forward slashes only — all process paths are normalized
// via pathutil.ToSlash before matching. Backslash variants are unnecessary.
// Matching is case-aware via pathutil.DefaultFS().Lower() (case-insensitive
// on Windows/macOS APFS, case-sensitive on Linux).
var KnownAgents = []AgentSignature{
	{
		Name:     "Claude Code",
		ExeNames: []string{"claude"},
		PathPatterns: []string{
			".local/bin/claude",          // Windows + Linux (self-update renames to .old.*)
			"AppData/Roaming/npm/claude", // Windows npm global install
			"/usr/local/bin/claude",      // macOS Homebrew
		},
	},
	{
		Name:     "Claude Desktop",
		ExeNames: []string{"Claude"},
		PathPatterns: []string{
			"WindowsApps/Claude",            // Windows MSIX alias
			"/Applications/Claude.app",      // macOS
			"Programs/claude/Claude",        // Windows user install (Squirrel)
			"AppData/Local/AnthropicClaude", // Windows per-user install
		},
	},
	{
		Name:     "Cursor",
		ExeNames: []string{"Cursor"},
		PathPatterns: []string{
			"Programs/cursor/Cursor",   // Windows
			"/Applications/Cursor.app", // macOS
		},
	},
	{
		Name:     "Windsurf",
		ExeNames: []string{"Windsurf"},
		PathPatterns: []string{
			"Programs/Windsurf/Windsurf", // Windows
			"/Applications/Windsurf.app", // macOS
		},
	},
	{
		Name:     "Codex",
		ExeNames: []string{"codex"},
	},
	{
		Name:     "Cline",
		ExeNames: []string{"cline"},
	},
	{
		Name:     "OpenCode",
		ExeNames: []string{"opencode"},
	},
	{
		Name:     "OpenClaw",
		ExeNames: []string{"openclaw"},
	},
	{
		Name:     "Neovim (mcphub)",
		ExeNames: []string{"nvim"},
	},
	{
		Name:     "Aider",
		ExeNames: []string{"aider"},
	},
	{
		Name: "Amazon Q",
		PathPatterns: []string{
			"Amazon/AWSCLIV2/q", // Windows
			"amazon-q/q",        // Homebrew
		},
	},
}

// Detect scans for running AI agent processes and returns their status.
// It cross-references with the registry to determine protection status.
func Detect() []DetectedAgent {
	procs, err := scanProcesses()
	if err != nil {
		log.Warn("process scan failed: %v", err)
		procs = nil
	}

	fs := pathutil.DefaultFS()
	var agents []DetectedAgent
	for _, sig := range KnownAgents {
		var pids []int
		var matchedName, matchedPath string

		for _, p := range procs {
			matched := false

			// Priority 1: full path matching (most reliable)
			if p.Path != "" && len(sig.PathPatterns) > 0 {
				// Normalize separators and apply filesystem case folding
				normPath := fs.Lower(pathutil.ToSlash(p.Path))
				for _, pattern := range sig.PathPatterns {
					normPattern := fs.Lower(pathutil.ToSlash(pattern))
					if strings.Contains(normPath, normPattern) {
						matched = true
						break
					}
				}
			}

			// Priority 2: exe name matching (fallback, case-sensitive to
			// distinguish e.g. "claude" (CLI) from "Claude" (Desktop))
			if !matched {
				matched = slices.Contains(sig.ExeNames, p.Name)
			}

			if matched {
				pids = append(pids, p.PID)
				if matchedName == "" {
					matchedName = p.Name
				}
				if matchedPath == "" && p.Path != "" {
					matchedPath = cleanExePath(p.Path)
				}
			}
		}

		// Check if this agent's config is patched via the registry
		patched := isRegistryPatched(sig.Name)

		if len(pids) > 0 && patched {
			agents = append(agents, DetectedAgent{Name: sig.Name, Status: "protected", PIDs: pids, ProcessName: matchedName, ExePath: matchedPath})
		} else if len(pids) > 0 {
			agents = append(agents, DetectedAgent{Name: sig.Name, Status: "running", PIDs: pids, ProcessName: matchedName, ExePath: matchedPath})
		} else if patched {
			agents = append(agents, DetectedAgent{Name: sig.Name, Status: "configured", PIDs: nil})
		}
	}
	return agents
}

// isRegistryPatched checks if the named agent was successfully patched by the daemon.
// For Claude Code, also checks if the PreToolUse hook is installed in ~/.claude/settings.json.
func isRegistryPatched(name string) bool {
	if registry.Default.IsPatched(name) {
		return true
	}
	// Claude Code is protected via PreToolUse hook even when MCP patching
	// returns ErrNothingPatched (no MCP servers in config to wrap).
	if name == "Claude Code" {
		return isClaudeHookInstalled()
	}
	return false
}

// isClaudeHookInstalled checks if ~/.claude/settings.json contains a crust PreToolUse hook.
func isClaudeHookInstalled() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	data, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		return false
	}
	// Quick string check — avoids JSON parsing overhead in the hot path.
	return strings.Contains(string(data), "evaluate-hook")
}

// cleanExePath strips self-update rename suffixes (e.g. ".old.1773623400727")
// from executable paths. Some tools (Claude Code) rename the running binary
// during auto-update; the OS reports the original path at process start time.
// Only strips ".old." from the basename to avoid corrupting directory paths
// like "/home/user/.old.cache/bin/claude".
func cleanExePath(p string) string {
	// Find the basename start (after last separator)
	lastSep := strings.LastIndexAny(p, `/\`)
	base := p[lastSep+1:] // works even when lastSep == -1
	if i := strings.Index(base, ".old."); i > 0 {
		return p[:lastSep+1] + base[:i]
	}
	return p
}
