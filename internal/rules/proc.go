package rules

import "strings"

// pathGuard is a hardcoded path protection that runs after symlink resolution.
// Each guard checks all normalized+resolved paths and blocks on match.
// Hardcoded in Go (not YAML) so they cannot be tampered with by agents.
type pathGuard struct {
	rule     string // e.g. "builtin:protect-proc"
	severity Severity
	check    func(paths []string) (bool, string)
	message  func(path string) string
}

// pathGuards is the registry of hardcoded path protections.
// Add new entries here — they are automatically applied in Evaluate() step 11.
var pathGuards = []pathGuard{
	{
		rule:     "builtin:protect-proc",
		severity: SeverityCritical,
		check:    hasProcPath,
		message: func(p string) string {
			return "Cannot access " + p + " — /proc may expose secrets, API keys, and process memory"
		},
	},
	{
		rule:     "builtin:protect-crypto-wallet",
		severity: SeverityCritical,
		check:    hasCryptoWalletPath,
		message:  func(p string) string { return "Cannot access " + p + " — crypto wallet directory" },
	},
}

// checkHardcodedPaths runs all registered path guards against the given paths.
// Returns a block result on first match, or nil if all pass.
func checkHardcodedPaths(paths []string) *MatchResult {
	for _, g := range pathGuards {
		if blocked, path := g.check(paths); blocked {
			m := NewMatch(g.rule, g.severity, ActionBlock, g.message(path))
			return &m
		}
	}
	return nil
}

// hasProcPath checks if any normalized path accesses /proc.
// On Linux, /proc exposes process environ, cmdline, memory, and file
// descriptors — all of which may contain API keys and secrets.
// On non-Linux platforms, /proc paths never appear so this is a no-op.
func hasProcPath(paths []string) (bool, string) {
	for _, p := range paths {
		if strings.HasPrefix(p, "/proc/") {
			return true, p
		}
	}
	return false, ""
}
