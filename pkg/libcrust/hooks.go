//go:build libcrust

package libcrust

import "github.com/BakeLens/crust/internal/hookutil"

// InstallClaudeHook installs a PreToolUse hook in ~/.claude/settings.json.
func InstallClaudeHook(crustBin string) error { return hookutil.Install(crustBin) }

// UninstallClaudeHook removes crust entries from ~/.claude/settings.json hooks.
func UninstallClaudeHook() error { return hookutil.Uninstall() }

// FormatHookResponse formats a raw eval result JSON into the PreToolUse hook response.
// Returns "" if allowed (fail-open).
func FormatHookResponse(evalResult string) string { return hookutil.FormatResponse(evalResult) }

// cleanupStaleHooksFile removes the old ~/.claude/hooks.json if it only
// contains crust hooks.
func cleanupStaleHooksFile() { hookutil.CleanupStaleFile() }
